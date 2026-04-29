"""
HuggingFace WAF Dataset Comprehensive Analysis
State-of-the-art statistical and visual analysis for cyber ML
"""

from __future__ import annotations

import json
import math
import os
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from scipy import stats
from sklearn.decomposition import PCA
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.feature_selection import mutual_info_classif

matplotlib.use("Agg")

sns.set_style("whitegrid")
plt.rcParams["figure.figsize"] = (12, 7)
plt.rcParams["font.size"] = 10


@dataclass
class SplitPlan:
    name: str
    ratios: Tuple[float, ...]
    labels: Tuple[str, ...]


class HuggingFaceWafAnalyzer:
    def __init__(
        self,
        csv_path: str,
        output_dir: str,
        text_col: Optional[str] = None,
        label_col: Optional[str] = None,
        sample_size: int = 20000,
        random_state: int = 42,
    ) -> None:
        self.csv_path = csv_path
        self.output_dir = output_dir
        self.text_col = text_col
        self.label_col = label_col
        self.sample_size = sample_size
        self.random_state = random_state
        self.df: pd.DataFrame | None = None
        self.df_features: pd.DataFrame | None = None
        self.label_encoder: LabelEncoder | None = None
        self.report: Dict[str, object] = {}

    def load_data(self) -> pd.DataFrame:
        print("Loading dataset...")
        df = pd.read_csv(self.csv_path, low_memory=False)

        if self.text_col is None:
            self.text_col = self._infer_text_col(df)
        if self.label_col is None:
            self.label_col = self._infer_label_col(df)

        if self.text_col not in df.columns or self.label_col not in df.columns:
            raise ValueError(
                f"Unable to find text/label columns. text_col={self.text_col}, label_col={self.label_col}"
            )

        self.df = df
        print(f"Loaded {len(df)} rows, {len(df.columns)} columns")
        print(f"Text column: {self.text_col}")
        print(f"Label column: {self.label_col}")
        return df

    def _infer_text_col(self, df: pd.DataFrame) -> str:
        candidates = ["text", "payload", "request", "url", "query", "content", "data"]
        for name in candidates:
            if name in df.columns:
                return name
        # Fallback: choose the longest average string column
        obj_cols = [c for c in df.columns if df[c].dtype == "object"]
        if not obj_cols:
            raise ValueError("No object columns found for text inference.")
        avg_len = {c: df[c].astype(str).str.len().mean() for c in obj_cols}
        return max(avg_len, key=avg_len.get)

    def _infer_label_col(self, df: pd.DataFrame) -> str:
        candidates = ["label", "class", "target", "y", "is_malicious", "is_attack"]
        for name in candidates:
            if name in df.columns:
                return name
        raise ValueError("No label column found for label inference.")

    def _ensure_output_dir(self) -> None:
        os.makedirs(self.output_dir, exist_ok=True)

    def _sanitize_text(self, series: pd.Series) -> pd.Series:
        return series.fillna("").astype(str)

    def compute_features(self) -> pd.DataFrame:
        assert self.df is not None
        text = self._sanitize_text(self.df[self.text_col])

        def char_entropy(s: str) -> float:
            if not s:
                return 0.0
            counts = np.array(list(pd.Series(list(s)).value_counts()))
            probs = counts / counts.sum()
            return float(-(probs * np.log2(probs)).sum())

        def max_run_length(s: str) -> int:
            if not s:
                return 0
            max_run = 1
            run = 1
            for i in range(1, len(s)):
                if s[i] == s[i - 1]:
                    run += 1
                    max_run = max(max_run, run)
                else:
                    run = 1
            return max_run

        suspicious_keywords = [
            "select", "union", "insert", "update", "delete", "drop", "sleep",
            "benchmark", "or 1=1", "../", "<script", "%3cscript", "javascript:",
            "onerror", "onload", "cmd=", "wget", "curl", "bash", "powershell",
        ]

        features = pd.DataFrame(index=self.df.index)
        features["text_length"] = text.str.len()
        features["word_count"] = text.str.split().str.len()
        features["unique_word_count"] = text.str.split().apply(lambda x: len(set(x)))
        features["digit_ratio"] = text.apply(lambda s: sum(ch.isdigit() for ch in s) / max(len(s), 1))
        features["upper_ratio"] = text.apply(lambda s: sum(ch.isupper() for ch in s) / max(len(s), 1))
        features["special_ratio"] = text.apply(
            lambda s: sum(not ch.isalnum() and not ch.isspace() for ch in s) / max(len(s), 1)
        )
        features["whitespace_ratio"] = text.apply(lambda s: sum(ch.isspace() for ch in s) / max(len(s), 1))
        features["non_ascii_ratio"] = text.apply(lambda s: sum(ord(ch) > 127 for ch in s) / max(len(s), 1))
        features["entropy"] = text.apply(char_entropy)
        features["max_run"] = text.apply(max_run_length)
        features["slash_count"] = text.str.count(r"/")
        features["dot_count"] = text.str.count(r"\.")
        features["param_count"] = text.str.count(r"\?") + text.str.count(r"&")
        features["path_depth"] = text.str.count(r"/")
        features["url_encoded_ratio"] = text.str.count(r"%[0-9A-Fa-f]{2}") / text.str.len().replace(0, 1)
        features["suspicious_keyword_count"] = text.str.lower().apply(
            lambda s: sum(1 for kw in suspicious_keywords if kw in s)
        )

        self.df_features = features
        return features

    def _encode_labels(self) -> np.ndarray:
        assert self.df is not None
        labels = self.df[self.label_col].astype(str)
        encoder = LabelEncoder()
        y = encoder.fit_transform(labels)
        self.label_encoder = encoder
        return y

    def compute_central_tendency(self) -> Dict[str, object]:
        assert self.df is not None
        stats_dict: Dict[str, object] = {}

        label_counts = self.df[self.label_col].value_counts()
        stats_dict["class_distribution"] = {
            "counts": label_counts.to_dict(),
            "ratio_max_min": float(label_counts.max() / max(label_counts.min(), 1)),
        }

        numeric_summary = self.df_features.describe().T
        numeric_summary["median"] = self.df_features.median()
        numeric_summary["mode"] = self.df_features.mode().iloc[0]
        stats_dict["numeric_center"] = numeric_summary[["mean", "median", "mode"]].round(4).to_dict()

        self.report["central_tendency"] = stats_dict
        return stats_dict

    def compute_spread_skewness(self) -> Dict[str, object]:
        stats_dict: Dict[str, object] = {}
        spread = self.df_features.describe().T[["std", "min", "max"]]
        spread["range"] = spread["max"] - spread["min"]
        spread["iqr"] = self.df_features.quantile(0.75) - self.df_features.quantile(0.25)
        spread["skewness"] = self.df_features.skew()
        spread["kurtosis"] = self.df_features.kurtosis()
        stats_dict["spread_skewness"] = spread.round(4).to_dict()

        self.report["spread_skewness"] = stats_dict
        return stats_dict

    def detect_outliers(self) -> Dict[str, object]:
        outliers: Dict[str, object] = {}
        for col in self.df_features.columns:
            series = self.df_features[col]
            q1 = series.quantile(0.25)
            q3 = series.quantile(0.75)
            iqr = q3 - q1
            lower = q1 - 1.5 * iqr
            upper = q3 + 1.5 * iqr
            iqr_outliers = series[(series < lower) | (series > upper)]

            z_scores = np.abs(stats.zscore(series, nan_policy="omit"))
            z_outliers = series[z_scores > 3]

            outliers[col] = {
                "iqr_outliers": {
                    "count": int(iqr_outliers.shape[0]),
                    "percentage": float(iqr_outliers.shape[0] / len(series) * 100),
                    "bounds": {"lower": float(lower), "upper": float(upper)},
                },
                "zscore_outliers": {
                    "count": int(z_outliers.shape[0]),
                    "percentage": float(z_outliers.shape[0] / len(series) * 100),
                },
            }

        self.report["outliers"] = outliers
        return outliers

    def analyze_correlations(self) -> Dict[str, object]:
        y = self._encode_labels()
        corr = self.df_features.corrwith(pd.Series(y, index=self.df_features.index))
        corr_dict = {k: round(v, 4) for k, v in corr.to_dict().items()}

        # Point-biserial correlation and mutual information
        pb_results = {}
        for col in self.df_features.columns:
            try:
                r, p = stats.pointbiserialr(y, self.df_features[col])
                pb_results[col] = {"r": round(float(r), 4), "p_value": round(float(p), 6)}
            except Exception:
                pb_results[col] = {"r": None, "p_value": None}

        mi = mutual_info_classif(self.df_features.fillna(0), y, random_state=self.random_state)
        mi_dict = {col: round(float(val), 4) for col, val in zip(self.df_features.columns, mi)}

        report = {
            "corr_with_label": corr_dict,
            "point_biserial": pb_results,
            "mutual_info": mi_dict,
        }

        self.report["correlations"] = report
        return report

    def analyze_distributions(self) -> Dict[str, object]:
        assert self.df is not None
        dist_report: Dict[str, object] = {}

        y = self._encode_labels()
        labels = self.label_encoder.inverse_transform(y)

        for col in self.df_features.columns:
            series = self.df_features[col]
            sample = series.sample(min(5000, len(series)), random_state=self.random_state)
            try:
                shapiro_stat, shapiro_p = stats.shapiro(sample)
                shapiro = {
                    "statistic": round(float(shapiro_stat), 4),
                    "p_value": round(float(shapiro_p), 6),
                    "is_normal": shapiro_p > 0.05,
                }
            except Exception:
                shapiro = {"statistic": None, "p_value": None, "is_normal": None}

            group_vals = {}
            for label in np.unique(labels):
                group_vals[label] = series[labels == label]
            if len(group_vals) == 2:
                (label_a, label_b) = list(group_vals.keys())
                ks_stat, ks_p = stats.ks_2samp(group_vals[label_a], group_vals[label_b])
                ks = {
                    "statistic": round(float(ks_stat), 4),
                    "p_value": round(float(ks_p), 6),
                    "significantly_different": ks_p < 0.05,
                    "label_a": label_a,
                    "label_b": label_b,
                }
            else:
                ks = {"statistic": None, "p_value": None, "significantly_different": None}

            dist_report[col] = {
                "shapiro": shapiro,
                "ks_test": ks,
            }

        self.report["distributions"] = dist_report
        return dist_report

    def assess_data_quality(self) -> Dict[str, object]:
        assert self.df is not None
        quality: Dict[str, object] = {}

        missing = self.df.isnull().sum()
        missing_pct = (missing / len(self.df) * 100).round(3)
        quality["missing"] = {
            col: {"count": int(missing[col]), "percentage": float(missing_pct[col])}
            for col in self.df.columns
            if missing[col] > 0
        }

        duplicates = self.df.duplicated().sum()
        quality["duplicates"] = {
            "count": int(duplicates),
            "percentage": float(duplicates / len(self.df) * 100),
        }

        text = self._sanitize_text(self.df[self.text_col])
        empty_text = text.str.strip().eq("").sum()
        quality["empty_text"] = {
            "count": int(empty_text),
            "percentage": float(empty_text / len(text) * 100),
        }

        # Same text, conflicting labels
        conflict_df = self.df[[self.text_col, self.label_col]].dropna()
        conflict_counts = conflict_df.groupby(self.text_col)[self.label_col].nunique()
        conflicts = conflict_counts[conflict_counts > 1].shape[0]
        quality["label_conflicts"] = {
            "count": int(conflicts),
            "percentage": float(conflicts / max(len(conflict_counts), 1) * 100),
        }

        self.report["quality"] = quality
        return quality

    def detect_bias(self) -> Dict[str, object]:
        assert self.df is not None
        bias: Dict[str, object] = {}

        label_counts = self.df[self.label_col].value_counts()
        ratio = float(label_counts.max() / max(label_counts.min(), 1))
        bias["class_imbalance"] = {
            "ratio_max_min": ratio,
            "severity": "severe" if ratio > 3 else "moderate" if ratio > 1.5 else "balanced",
        }

        # Length bias by class
        labels = self.df[self.label_col].astype(str)
        lengths = self.df_features["text_length"]
        length_by_class = lengths.groupby(labels).describe()[["mean", "std", "min", "max"]]
        bias["length_by_class"] = length_by_class.round(3).to_dict()

        self.report["bias"] = bias
        return bias

    def compute_rating(self) -> Dict[str, object]:
        quality = self.report.get("quality", {})
        bias = self.report.get("bias", {})
        outliers = self.report.get("outliers", {})

        missing_pct = sum(v["percentage"] for v in quality.get("missing", {}).values())
        dup_pct = quality.get("duplicates", {}).get("percentage", 0.0)
        conflict_pct = quality.get("label_conflicts", {}).get("percentage", 0.0)
        imbalance = bias.get("class_imbalance", {}).get("ratio_max_min", 1.0)
        outlier_pct = outliers.get("text_length", {}).get("iqr_outliers", {}).get("percentage", 0.0)

        score = 100.0
        score -= min(40.0, missing_pct * 0.5)
        score -= min(25.0, dup_pct * 0.5)
        score -= min(20.0, conflict_pct * 1.0)
        score -= min(20.0, math.log10(max(imbalance, 1.0)) * 15.0)
        score -= min(10.0, outlier_pct * 0.2)
        score = max(score, 0.0)

        rating = {
            "training_readiness_score": round(score, 2),
            "components": {
                "missing_pct": round(missing_pct, 3),
                "duplicates_pct": round(dup_pct, 3),
                "label_conflicts_pct": round(conflict_pct, 3),
                "class_imbalance_ratio": round(float(imbalance), 3),
                "text_length_outliers_pct": round(float(outlier_pct), 3),
            },
        }

        self.report["rating"] = rating
        return rating

    def create_plots(self) -> None:
        assert self.df is not None
        self._ensure_output_dir()

        labels = self.df[self.label_col].astype(str)
        text = self._sanitize_text(self.df[self.text_col])

        # Class distribution
        plt.figure()
        labels.value_counts().plot(kind="bar", color=["#4C78A8", "#F58518", "#54A24B"])
        plt.title("Class Distribution")
        plt.xlabel("Label")
        plt.ylabel("Count")
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, "class_distribution.png"))
        plt.close()

        # Length distribution by class
        plt.figure()
        for label in labels.unique():
            subset = self.df_features.loc[labels == label, "text_length"]
            sns.kdeplot(subset, label=label, fill=False)
        plt.title("Text Length KDE by Class")
        plt.xlabel("Text length")
        plt.ylabel("Density")
        plt.legend()
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, "length_kde_by_class.png"))
        plt.close()

        plt.figure()
        sns.boxplot(x=labels, y=self.df_features["text_length"])
        plt.title("Text Length Boxplot by Class")
        plt.xlabel("Label")
        plt.ylabel("Text length")
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, "length_boxplot_by_class.png"))
        plt.close()

        # Correlation heatmap
        plt.figure(figsize=(10, 8))
        corr = self.df_features.corr()
        sns.heatmap(corr, cmap="coolwarm", center=0, linewidths=0.5)
        plt.title("Feature Correlation Heatmap")
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, "feature_correlation_heatmap.png"))
        plt.close()

        # Pairplot for top correlated features
        corr_with_label = pd.Series(self.report["correlations"]["corr_with_label"]).abs().sort_values(ascending=False)
        top_cols = list(corr_with_label.head(5).index)
        sample = self.df_features[top_cols].sample(
            min(self.sample_size, len(self.df_features)), random_state=self.random_state
        )
        sample["label"] = labels.loc[sample.index].values
        sns.pairplot(sample, hue="label", corner=True, plot_kws={"alpha": 0.3, "s": 12})
        plt.savefig(os.path.join(self.output_dir, "pairplot_top_features.png"))
        plt.close()

        # TF-IDF PCA scatter
        tfidf_sample = text.sample(min(5000, self.sample_size, len(text)), random_state=self.random_state)
        tfidf_labels = labels.loc[tfidf_sample.index]
        vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 2), min_df=2)
        X = vectorizer.fit_transform(tfidf_sample)
        pca = PCA(n_components=2, random_state=self.random_state)
        coords = pca.fit_transform(X.toarray())
        plt.figure()
        sns.scatterplot(x=coords[:, 0], y=coords[:, 1], hue=tfidf_labels, s=14, alpha=0.5)
        plt.title("TF-IDF PCA Projection")
        plt.xlabel("PC1")
        plt.ylabel("PC2")
        plt.legend()
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, "tfidf_pca_scatter.png"))
        plt.close()

        # Top TF-IDF terms per class
        top_terms = self._top_terms_by_class(vectorizer, tfidf_sample, tfidf_labels)
        for label, terms in top_terms.items():
            plt.figure(figsize=(10, 6))
            sns.barplot(x=[t[1] for t in terms], y=[t[0] for t in terms], color="#4C78A8")
            plt.title(f"Top TF-IDF Terms ({label})")
            plt.xlabel("Mean TF-IDF")
            plt.ylabel("Term")
            plt.tight_layout()
            filename = f"top_terms_{re.sub(r'[^a-zA-Z0-9_-]+', '_', label)}.png"
            plt.savefig(os.path.join(self.output_dir, filename))
            plt.close()

        # Missingness bar
        missing = self.df.isnull().mean().sort_values(ascending=False)
        missing = missing[missing > 0]
        if not missing.empty:
            plt.figure()
            missing.plot(kind="bar", color="#E45756")
            plt.title("Missingness by Column")
            plt.ylabel("Fraction Missing")
            plt.tight_layout()
            plt.savefig(os.path.join(self.output_dir, "missingness_by_column.png"))
            plt.close()

    def _top_terms_by_class(
        self,
        vectorizer: TfidfVectorizer,
        texts: pd.Series,
        labels: pd.Series,
        top_n: int = 12,
    ) -> Dict[str, List[Tuple[str, float]]]:
        X = vectorizer.transform(texts)
        vocab = np.array(vectorizer.get_feature_names_out())
        results: Dict[str, List[Tuple[str, float]]] = {}
        for label in labels.unique():
            idx = labels[labels == label].index
            class_matrix = X[labels.index.isin(idx)]
            mean_tfidf = class_matrix.mean(axis=0).A1
            top_idx = mean_tfidf.argsort()[::-1][:top_n]
            results[label] = [(vocab[i], float(mean_tfidf[i])) for i in top_idx]
        return results

    def generate_splits(self) -> Dict[str, object]:
        assert self.df is not None
        self._ensure_output_dir()

        df_model = self.df.dropna(subset=[self.text_col, self.label_col]).copy()
        labels = df_model[self.label_col].astype(str)

        split_dir = os.path.join(self.output_dir, "splits")
        os.makedirs(split_dir, exist_ok=True)

        plans = [
            SplitPlan("split_80_20", (0.8, 0.2), ("train", "test")),
            SplitPlan("split_80_10_10", (0.8, 0.1, 0.1), ("train", "val", "test")),
            SplitPlan("split_70_15_15", (0.7, 0.15, 0.15), ("train", "val", "test")),
            SplitPlan("split_60_20_20", (0.6, 0.2, 0.2), ("train", "val", "test")),
            SplitPlan("split_40_20_20_10_10", (0.4, 0.2, 0.2, 0.1, 0.1), ("train", "val", "test", "holdout_a", "holdout_b")),
        ]

        summary: Dict[str, object] = {}
        for plan in plans:
            plan_dir = os.path.join(split_dir, plan.name)
            os.makedirs(plan_dir, exist_ok=True)

            remaining_df = df_model
            remaining_labels = labels
            splits: Dict[str, pd.DataFrame] = {}

            remaining_ratios = list(plan.ratios)
            for ratio, label_name in zip(plan.ratios[:-1], plan.labels[:-1]):
                remaining_total = sum(remaining_ratios)
                split_ratio = ratio / remaining_total
                train_df, remaining_df, train_labels, remaining_labels = train_test_split(
                    remaining_df,
                    remaining_labels,
                    train_size=split_ratio,
                    stratify=remaining_labels,
                    random_state=self.random_state,
                )
                splits[label_name] = train_df
                remaining_ratios = remaining_ratios[1:]

            splits[plan.labels[-1]] = remaining_df

            plan_summary = {}
            for label_name, split_df in splits.items():
                out_path = os.path.join(plan_dir, f"{label_name}.csv")
                split_df.to_csv(out_path, index=False)
                counts = split_df[self.label_col].value_counts().to_dict()
                plan_summary[label_name] = {
                    "rows": int(len(split_df)),
                    "class_counts": counts,
                }

            summary[plan.name] = plan_summary

        self.report["splits"] = summary
        return summary

    def recommend_feature_engineering(self) -> List[str]:
        recommendations = [
            "Use character n-grams (3-5) for robust detection of obfuscated payloads.",
            "Add URL decoding and normalization (percent-decoding, lowercase, strip repeated delimiters).",
            "Extract query parameter keys/values separately and encode key presence as binary features.",
            "Compute entropy, max run length, and special character density to capture obfuscation.",
            "Add keyword-based indicators for SQLi/XSS/RCE patterns and their counts.",
            "Separate HTTP method, path depth, and file extension features if present in text.",
            "Use TF-IDF with sublinear term frequency and max_df filtering for sparse robustness.",
            "Consider calibrated class weights or focal loss to manage imbalance.",
        ]
        self.report["feature_engineering"] = recommendations
        return recommendations

    def write_report(self) -> None:
        self._ensure_output_dir()
        report_path = os.path.join(self.output_dir, "analysis_report.json")
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(self._to_builtin(self.report), f, indent=2)

        summary_path = os.path.join(self.output_dir, "analysis_summary.md")
        with open(summary_path, "w", encoding="utf-8") as f:
            f.write("# HuggingFace WAF Dataset Analysis Summary\n\n")
            f.write("## Key Findings\n")
            class_dist = self.report.get("central_tendency", {}).get("class_distribution", {})
            f.write(f"- Class distribution: {class_dist}\n")
            rating = self.report.get("rating", {})
            f.write(f"- Training readiness score: {rating.get('training_readiness_score')}\n")
            f.write("\n## Feature Engineering Recommendations\n")
            for rec in self.report.get("feature_engineering", []):
                f.write(f"- {rec}\n")

    def run(self) -> None:
        self.load_data()
        self.compute_features()
        self.compute_central_tendency()
        self.compute_spread_skewness()
        self.detect_outliers()
        self.analyze_correlations()
        self.analyze_distributions()
        self.assess_data_quality()
        self.detect_bias()
        self.compute_rating()
        self.create_plots()
        self.generate_splits()
        self.recommend_feature_engineering()
        self.write_report()
        print(f"Analysis complete. Outputs saved to {self.output_dir}")

    def _to_builtin(self, obj: object) -> object:
        if isinstance(obj, dict):
            return {k: self._to_builtin(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._to_builtin(v) for v in obj]
        if isinstance(obj, tuple):
            return [self._to_builtin(v) for v in obj]
        if isinstance(obj, (np.integer, np.floating)):
            return obj.item()
        if isinstance(obj, np.bool_):
            return bool(obj)
        return obj


def main() -> None:
    base_dir = os.path.dirname(__file__)
    csv_path = os.path.join(base_dir, "huggingface_full.csv")
    output_dir = os.path.join(base_dir, "analysis_output", "huggingface_full")

    analyzer = HuggingFaceWafAnalyzer(
        csv_path=csv_path,
        output_dir=output_dir,
        text_col="text",
        label_col="label",
        sample_size=20000,
    )
    analyzer.run()


if __name__ == "__main__":
    main()
