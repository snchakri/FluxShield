"""
CSIC 2010 Dataset Comprehensive Analysis
State-of-the-art statistical and visual analysis for cyber ML
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from scipy import stats
from scipy.stats import chi2_contingency, ks_2samp
from sklearn.preprocessing import LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.decomposition import PCA
import warnings
import json
from collections import Counter
import re

warnings.filterwarnings('ignore')

# Set visualization style
sns.set_style("whitegrid")
plt.rcParams['figure.figsize'] = (12, 8)
plt.rcParams['font.size'] = 10

class CSICAnalyzer:
    def __init__(self, csv_path):
        """Initialize analyzer with dataset path"""
        self.csv_path = csv_path
        self.df = None
        self.feature_stats = {}
        self.quality_report = {}
        self.split_recommendations = {}
        
    def load_data(self):
        """Load and preprocess dataset"""
        print("Loading dataset...")
        self.df = pd.read_csv(self.csv_path, low_memory=False)
        
        # Fix first column name if it's unnamed
        if self.df.columns[0].startswith('Unnamed') or self.df.columns[0].startswith('H1'):
            self.df = self.df.iloc[:, 1:]  # Drop first unnamed column
        
        print(f"Loaded {len(self.df)} rows, {len(self.df.columns)} columns")
        print(f"Columns: {list(self.df.columns)}")
        
        # Rename classification column for consistency
        if 'classification' in self.df.columns:
            self.df['label'] = self.df['classification'].apply(lambda x: 'malicious' if x == 1 else 'benign')
        
        return self.df
    
    def compute_central_tendency(self):
        """Compute center metrics for numerical and categorical features"""
        print("\n" + "="*80)
        print("1. CENTRAL TENDENCY ANALYSIS")
        print("="*80)
        
        stats_dict = {}
        
        # Class distribution (most important for cyber ML)
        class_dist = self.df['label'].value_counts()
        stats_dict['class_distribution'] = {
            'benign': int(class_dist.get('benign', 0)),
            'malicious': int(class_dist.get('malicious', 0)),
            'ratio': round(class_dist.get('benign', 0) / class_dist.get('malicious', 1), 2)
        }
        
        print(f"\nClass Distribution:")
        print(f"  Benign: {stats_dict['class_distribution']['benign']}")
        print(f"  Malicious: {stats_dict['class_distribution']['malicious']}")
        print(f"  Ratio (B/M): {stats_dict['class_distribution']['ratio']}")
        
        # Text length analysis
        if 'URL' in self.df.columns:
            self.df['url_length'] = self.df['URL'].fillna('').str.len()
            stats_dict['url_length'] = {
                'mean': round(self.df['url_length'].mean(), 2),
                'median': round(self.df['url_length'].median(), 2),
                'mode': int(self.df['url_length'].mode()[0]) if len(self.df['url_length'].mode()) > 0 else 0
            }
            print(f"\nURL Length:")
            print(f"  Mean: {stats_dict['url_length']['mean']}")
            print(f"  Median: {stats_dict['url_length']['median']}")
            print(f"  Mode: {stats_dict['url_length']['mode']}")
        
        # HTTP Method distribution
        if 'Method' in self.df.columns:
            method_dist = self.df['Method'].value_counts().to_dict()
            stats_dict['http_methods'] = method_dist
            print(f"\nHTTP Methods:")
            for method, count in list(method_dist.items())[:5]:
                print(f"  {method}: {count}")
        
        self.feature_stats['central_tendency'] = stats_dict
        return stats_dict
    
    def compute_spread_skewness(self):
        """Compute spread, variance, skewness for numerical features"""
        print("\n" + "="*80)
        print("2. SPREAD & SKEWNESS ANALYSIS")
        print("="*80)
        
        stats_dict = {}
        
        # URL length statistics
        if 'url_length' in self.df.columns:
            url_stats = {
                'std': round(self.df['url_length'].std(), 2),
                'variance': round(self.df['url_length'].var(), 2),
                'range': int(self.df['url_length'].max() - self.df['url_length'].min()),
                'iqr': round(self.df['url_length'].quantile(0.75) - self.df['url_length'].quantile(0.25), 2),
                'skewness': round(self.df['url_length'].skew(), 3),
                'kurtosis': round(self.df['url_length'].kurtosis(), 3)
            }
            stats_dict['url_length'] = url_stats
            
            print(f"\nURL Length Distribution:")
            print(f"  Std Dev: {url_stats['std']}")
            print(f"  Variance: {url_stats['variance']}")
            print(f"  Range: {url_stats['range']}")
            print(f"  IQR: {url_stats['iqr']}")
            print(f"  Skewness: {url_stats['skewness']} {'(right-skewed)' if url_stats['skewness'] > 0 else '(left-skewed)'}")
            print(f"  Kurtosis: {url_stats['kurtosis']} {'(heavy-tailed)' if url_stats['kurtosis'] > 0 else '(light-tailed)'}")
        
        # Content length analysis
        if 'content' in self.df.columns:
            self.df['content_length'] = self.df['content'].fillna('').str.len()
            content_stats = {
                'mean': round(self.df['content_length'].mean(), 2),
                'std': round(self.df['content_length'].std(), 2),
                'skewness': round(self.df['content_length'].skew(), 3)
            }
            stats_dict['content_length'] = content_stats
            print(f"\nContent Length:")
            print(f"  Mean: {content_stats['mean']}, Std: {content_stats['std']}")
            print(f"  Skewness: {content_stats['skewness']}")
        
        self.feature_stats['spread_skewness'] = stats_dict
        return stats_dict
    
    def detect_outliers(self):
        """Detect outliers using IQR and Z-score methods"""
        print("\n" + "="*80)
        print("3. OUTLIER DETECTION")
        print("="*80)
        
        outliers_dict = {}
        
        if 'url_length' in self.df.columns:
            # IQR method
            Q1 = self.df['url_length'].quantile(0.25)
            Q3 = self.df['url_length'].quantile(0.75)
            IQR = Q3 - Q1
            lower_bound = Q1 - 1.5 * IQR
            upper_bound = Q3 + 1.5 * IQR
            
            iqr_outliers = self.df[(self.df['url_length'] < lower_bound) | (self.df['url_length'] > upper_bound)]
            
            # Z-score method
            z_scores = np.abs(stats.zscore(self.df['url_length']))
            z_outliers = self.df[z_scores > 3]
            
            outliers_dict['url_length'] = {
                'iqr_method': {
                    'count': len(iqr_outliers),
                    'percentage': round(len(iqr_outliers) / len(self.df) * 100, 2),
                    'bounds': {'lower': round(lower_bound, 2), 'upper': round(upper_bound, 2)}
                },
                'zscore_method': {
                    'count': len(z_outliers),
                    'percentage': round(len(z_outliers) / len(self.df) * 100, 2)
                }
            }
            
            print(f"\nURL Length Outliers:")
            print(f"  IQR Method: {outliers_dict['url_length']['iqr_method']['count']} ({outliers_dict['url_length']['iqr_method']['percentage']}%)")
            print(f"  Z-score Method (|z| > 3): {outliers_dict['url_length']['zscore_method']['count']} ({outliers_dict['url_length']['zscore_method']['percentage']}%)")
            print(f"  IQR Bounds: [{outliers_dict['url_length']['iqr_method']['bounds']['lower']}, {outliers_dict['url_length']['iqr_method']['bounds']['upper']}]")
        
        self.feature_stats['outliers'] = outliers_dict
        return outliers_dict
    
    def analyze_correlations(self):
        """Analyze feature correlations"""
        print("\n" + "="*80)
        print("4. CORRELATION ANALYSIS")
        print("="*80)
        
        corr_dict = {}
        
        # Create numerical features for correlation
        numerical_features = pd.DataFrame()
        
        if 'url_length' in self.df.columns:
            numerical_features['url_length'] = self.df['url_length']
        
        if 'content_length' in self.df.columns:
            numerical_features['content_length'] = self.df['content_length']
        
        # Binary encoding of label
        numerical_features['is_malicious'] = (self.df['label'] == 'malicious').astype(int)
        
        # Special characters count in URL
        if 'URL' in self.df.columns:
            numerical_features['special_char_count'] = self.df['URL'].fillna('').apply(
                lambda x: len(re.findall(r'[^a-zA-Z0-9\s]', x))
            )
            numerical_features['digit_count'] = self.df['URL'].fillna('').apply(
                lambda x: sum(c.isdigit() for c in x)
            )
        
        # Compute correlation matrix
        corr_matrix = numerical_features.corr()
        
        # Focus on correlation with maliciousness
        malicious_corr = corr_matrix['is_malicious'].sort_values(ascending=False)
        
        corr_dict['with_malicious'] = {
            k: round(v, 3) for k, v in malicious_corr.to_dict().items() if k != 'is_malicious'
        }
        
        print(f"\nCorrelation with Maliciousness:")
        for feature, corr in corr_dict['with_malicious'].items():
            print(f"  {feature}: {corr}")
        
        # Chi-square test for categorical features
        if 'Method' in self.df.columns:
            contingency_table = pd.crosstab(self.df['Method'], self.df['label'])
            chi2, p_value, dof, expected = chi2_contingency(contingency_table)
            
            corr_dict['method_label_chi2'] = {
                'chi2': round(chi2, 2),
                'p_value': round(p_value, 6),
                'significant': p_value < 0.05
            }
            
            print(f"\nHTTP Method vs Label (Chi-square test):")
            print(f"  Chi2: {corr_dict['method_label_chi2']['chi2']}")
            print(f"  P-value: {corr_dict['method_label_chi2']['p_value']}")
            print(f"  Significant: {corr_dict['method_label_chi2']['significant']}")
        
        self.feature_stats['correlations'] = corr_dict
        self.numerical_features = numerical_features
        self.corr_matrix = corr_matrix
        
        return corr_dict
    
    def analyze_distributions(self):
        """Analyze probability distributions"""
        print("\n" + "="*80)
        print("5. PROBABILITY DISTRIBUTION ANALYSIS")
        print("="*80)
        
        dist_dict = {}
        
        if 'url_length' in self.df.columns:
            # Normality test (Shapiro-Wilk for sample, Anderson-Darling for larger)
            # Use sample for Shapiro-Wilk (max 5000 samples)
            sample_size = min(5000, len(self.df))
            sample_data = self.df['url_length'].sample(sample_size, random_state=42)
            
            shapiro_stat, shapiro_p = stats.shapiro(sample_data)
            
            # Kolmogorov-Smirnov test for distribution comparison
            benign_urls = self.df[self.df['label'] == 'benign']['url_length']
            malicious_urls = self.df[self.df['label'] == 'malicious']['url_length']
            
            ks_stat, ks_p = ks_2samp(benign_urls, malicious_urls)
            
            dist_dict['url_length'] = {
                'normality_test': {
                    'shapiro_stat': round(shapiro_stat, 4),
                    'shapiro_p': round(shapiro_p, 6),
                    'is_normal': shapiro_p > 0.05
                },
                'ks_test_benign_vs_malicious': {
                    'ks_stat': round(ks_stat, 4),
                    'p_value': round(ks_p, 6),
                    'significantly_different': ks_p < 0.05
                }
            }
            
            print(f"\nURL Length Distribution:")
            print(f"  Normality Test (Shapiro-Wilk):")
            print(f"    Statistic: {dist_dict['url_length']['normality_test']['shapiro_stat']}")
            print(f"    P-value: {dist_dict['url_length']['normality_test']['shapiro_p']}")
            print(f"    Is Normal: {dist_dict['url_length']['normality_test']['is_normal']}")
            print(f"\n  KS Test (Benign vs Malicious):")
            print(f"    Statistic: {dist_dict['url_length']['ks_test_benign_vs_malicious']['ks_stat']}")
            print(f"    P-value: {dist_dict['url_length']['ks_test_benign_vs_malicious']['p_value']}")
            print(f"    Significantly Different: {dist_dict['url_length']['ks_test_benign_vs_malicious']['significantly_different']}")
        
        self.feature_stats['distributions'] = dist_dict
        return dist_dict
    
    def assess_data_quality(self):
        """Comprehensive data quality assessment"""
        print("\n" + "="*80)
        print("6. DATA QUALITY ASSESSMENT")
        print("="*80)
        
        quality = {}
        
        # Missing data analysis
        missing_counts = self.df.isnull().sum()
        missing_pct = (missing_counts / len(self.df) * 100).round(2)
        
        quality['missing_data'] = {
            col: {'count': int(count), 'percentage': float(missing_pct[col])}
            for col, count in missing_counts.items() if count > 0
        }
        
        print(f"\nMissing Data:")
        if quality['missing_data']:
            for col, stats in quality['missing_data'].items():
                print(f"  {col}: {stats['count']} ({stats['percentage']}%)")
        else:
            print("  No missing data detected!")
        
        # Duplicate detection
        duplicates = self.df.duplicated().sum()
        quality['duplicates'] = {
            'count': int(duplicates),
            'percentage': round(duplicates / len(self.df) * 100, 2)
        }
        
        print(f"\nDuplicates:")
        print(f"  Count: {quality['duplicates']['count']} ({quality['duplicates']['percentage']}%)")
        
        # Class imbalance analysis
        class_counts = self.df['label'].value_counts()
        imbalance_ratio = class_counts.max() / class_counts.min()
        
        quality['class_imbalance'] = {
            'ratio': round(imbalance_ratio, 2),
            'severity': 'severe' if imbalance_ratio > 3 else 'moderate' if imbalance_ratio > 1.5 else 'balanced'
        }
        
        print(f"\nClass Imbalance:")
        print(f"  Ratio: {quality['class_imbalance']['ratio']}")
        print(f"  Severity: {quality['class_imbalance']['severity']}")
        
        # Data consistency checks
        quality['consistency'] = {}
        
        # Check for empty/whitespace-only values
        if 'URL' in self.df.columns:
            empty_urls = self.df['URL'].fillna('').str.strip().eq('').sum()
            quality['consistency']['empty_urls'] = {
                'count': int(empty_urls),
                'percentage': round(empty_urls / len(self.df) * 100, 2)
            }
            print(f"\nConsistency Issues:")
            print(f"  Empty URLs: {quality['consistency']['empty_urls']['count']} ({quality['consistency']['empty_urls']['percentage']}%)")
        
        self.quality_report = quality
        return quality
    
    def detect_bias(self):
        """Detect potential biases in the dataset"""
        print("\n" + "="*80)
        print("7. BIAS DETECTION")
        print("="*80)
        
        bias_report = {}
        
        # Temporal bias (if timestamps available)
        # Feature representation bias
        if 'Method' in self.df.columns:
            method_by_class = pd.crosstab(self.df['Method'], self.df['label'], normalize='columns') * 100
            
            bias_report['method_distribution'] = {
                'benign': method_by_class['benign'].to_dict(),
                'malicious': method_by_class['malicious'].to_dict()
            }
            
            print(f"\nHTTP Method Distribution by Class:")
            print(f"  Top methods in Benign:")
            for method, pct in sorted(bias_report['method_distribution']['benign'].items(), 
                                     key=lambda x: x[1], reverse=True)[:3]:
                print(f"    {method}: {pct:.2f}%")
            
            print(f"  Top methods in Malicious:")
            for method, pct in sorted(bias_report['method_distribution']['malicious'].items(), 
                                     key=lambda x: x[1], reverse=True)[:3]:
                print(f"    {method}: {pct:.2f}%")
        
        # URL pattern bias
        if 'URL' in self.df.columns:
            # Check for over-representation of specific patterns
            benign_urls = self.df[self.df['label'] == 'benign']['URL'].fillna('')
            malicious_urls = self.df[self.df['label'] == 'malicious']['URL'].fillna('')
            
            # Common substrings
            def get_common_patterns(urls, top_n=5):
                patterns = []
                for url in urls.head(1000):  # Sample for performance
                    patterns.extend([p for p in url.split('/') if len(p) > 3])
                return Counter(patterns).most_common(top_n)
            
            bias_report['url_patterns'] = {
                'benign_common': [{'pattern': p, 'count': c} for p, c in get_common_patterns(benign_urls)],
                'malicious_common': [{'pattern': p, 'count': c} for p, c in get_common_patterns(malicious_urls)]
            }
            
            print(f"\nCommon URL Patterns (sample):")
            print(f"  Benign:")
            for item in bias_report['url_patterns']['benign_common'][:3]:
                print(f"    {item['pattern']}: {item['count']}")
            print(f"  Malicious:")
            for item in bias_report['url_patterns']['malicious_common'][:3]:
                print(f"    {item['pattern']}: {item['count']}")
        
        self.quality_report['bias'] = bias_report
        return bias_report
    
    def generate_visualizations(self):
        """Generate comprehensive visualizations"""
        print("\n" + "="*80)
        print("8. GENERATING VISUALIZATIONS")
        print("="*80)
        
        output_dir = "analysis_output"
        import os
        os.makedirs(output_dir, exist_ok=True)
        
        # 1. Class Distribution Pie Chart
        plt.figure(figsize=(10, 6))
        class_counts = self.df['label'].value_counts()
        plt.pie(class_counts, labels=class_counts.index, autopct='%1.1f%%', startangle=90,
                colors=['#2ecc71', '#e74c3c'])
        plt.title('Class Distribution: Benign vs Malicious', fontsize=14, fontweight='bold')
        plt.savefig(f'{output_dir}/01_class_distribution.png', dpi=300, bbox_inches='tight')
        print(f"  ✓ Saved: 01_class_distribution.png")
        plt.close()
        
        # 2. URL Length Distribution by Class
        if 'url_length' in self.df.columns:
            plt.figure(figsize=(12, 6))
            benign = self.df[self.df['label'] == 'benign']['url_length']
            malicious = self.df[self.df['label'] == 'malicious']['url_length']
            
            plt.hist([benign, malicious], bins=50, label=['Benign', 'Malicious'],
                    alpha=0.7, color=['#2ecc71', '#e74c3c'])
            plt.xlabel('URL Length', fontsize=12)
            plt.ylabel('Frequency', fontsize=12)
            plt.title('URL Length Distribution by Class', fontsize=14, fontweight='bold')
            plt.legend()
            plt.grid(alpha=0.3)
            plt.savefig(f'{output_dir}/02_url_length_distribution.png', dpi=300, bbox_inches='tight')
            print(f"  ✓ Saved: 02_url_length_distribution.png")
            plt.close()
            
            # 3. Box Plot for URL Length
            plt.figure(figsize=(10, 6))
            self.df.boxplot(column='url_length', by='label', figsize=(10, 6),
                           patch_artist=True)
            plt.suptitle('')
            plt.title('URL Length Distribution by Class (Box Plot)', fontsize=14, fontweight='bold')
            plt.xlabel('Class', fontsize=12)
            plt.ylabel('URL Length', fontsize=12)
            plt.savefig(f'{output_dir}/03_url_length_boxplot.png', dpi=300, bbox_inches='tight')
            print(f"  ✓ Saved: 03_url_length_boxplot.png")
            plt.close()
        
        # 4. Correlation Heatmap
        if hasattr(self, 'corr_matrix'):
            plt.figure(figsize=(10, 8))
            sns.heatmap(self.corr_matrix, annot=True, cmap='coolwarm', center=0,
                       fmt='.2f', square=True, linewidths=1)
            plt.title('Feature Correlation Heatmap', fontsize=14, fontweight='bold')
            plt.tight_layout()
            plt.savefig(f'{output_dir}/04_correlation_heatmap.png', dpi=300, bbox_inches='tight')
            print(f"  ✓ Saved: 04_correlation_heatmap.png")
            plt.close()
        
        # 5. HTTP Method Distribution
        if 'Method' in self.df.columns:
            plt.figure(figsize=(12, 6))
            method_counts = self.df.groupby(['Method', 'label']).size().unstack(fill_value=0)
            method_counts.plot(kind='bar', stacked=False, color=['#2ecc71', '#e74c3c'])
            plt.title('HTTP Method Distribution by Class', fontsize=14, fontweight='bold')
            plt.xlabel('HTTP Method', fontsize=12)
            plt.ylabel('Count', fontsize=12)
            plt.legend(title='Class')
            plt.xticks(rotation=45)
            plt.grid(alpha=0.3, axis='y')
            plt.tight_layout()
            plt.savefig(f'{output_dir}/05_method_distribution.png', dpi=300, bbox_inches='tight')
            print(f"  ✓ Saved: 05_method_distribution.png")
            plt.close()
        
        # 6. Missing Data Visualization
        if self.quality_report.get('missing_data'):
            plt.figure(figsize=(12, 6))
            missing_df = pd.DataFrame({
                'Column': list(self.quality_report['missing_data'].keys()),
                'Missing %': [v['percentage'] for v in self.quality_report['missing_data'].values()]
            })
            plt.barh(missing_df['Column'], missing_df['Missing %'], color='#e74c3c')
            plt.xlabel('Missing Data (%)', fontsize=12)
            plt.title('Missing Data by Column', fontsize=14, fontweight='bold')
            plt.grid(alpha=0.3, axis='x')
            plt.tight_layout()
            plt.savefig(f'{output_dir}/06_missing_data.png', dpi=300, bbox_inches='tight')
            print(f"  ✓ Saved: 06_missing_data.png")
            plt.close()
        
        # 7. PCA Visualization (if we have numerical features)
        if hasattr(self, 'numerical_features') and len(self.numerical_features.columns) >= 3:
            plt.figure(figsize=(10, 8))
            features_for_pca = self.numerical_features.drop('is_malicious', axis=1)
            
            # Sample for performance
            sample_size = min(5000, len(features_for_pca))
            sample_idx = np.random.choice(len(features_for_pca), sample_size, replace=False)
            
            pca = PCA(n_components=2)
            components = pca.fit_transform(features_for_pca.iloc[sample_idx])
            
            labels_sample = self.df.iloc[sample_idx]['label']
            
            plt.scatter(components[labels_sample == 'benign', 0],
                       components[labels_sample == 'benign', 1],
                       alpha=0.5, label='Benign', color='#2ecc71', s=20)
            plt.scatter(components[labels_sample == 'malicious', 0],
                       components[labels_sample == 'malicious', 1],
                       alpha=0.5, label='Malicious', color='#e74c3c', s=20)
            plt.xlabel(f'PC1 ({pca.explained_variance_ratio_[0]:.1%} variance)', fontsize=12)
            plt.ylabel(f'PC2 ({pca.explained_variance_ratio_[1]:.1%} variance)', fontsize=12)
            plt.title('PCA: Feature Space Visualization', fontsize=14, fontweight='bold')
            plt.legend()
            plt.grid(alpha=0.3)
            plt.tight_layout()
            plt.savefig(f'{output_dir}/07_pca_visualization.png', dpi=300, bbox_inches='tight')
            print(f"  ✓ Saved: 07_pca_visualization.png")
            plt.close()
        
        print(f"\n  All visualizations saved to: {output_dir}/")
        
        return output_dir
    
    def compute_training_rating(self):
        """Compute overall dataset rating for ML training"""
        print("\n" + "="*80)
        print("9. DATASET TRAINING QUALITY RATING")
        print("="*80)
        
        rating = {
            'components': {},
            'overall_score': 0,
            'grade': '',
            'recommendations': []
        }
        
        # 1. Completeness Score (0-20 points)
        if self.quality_report.get('missing_data'):
            avg_missing = np.mean([v['percentage'] for v in self.quality_report['missing_data'].values()])
            completeness = max(0, 20 - avg_missing * 2)
        else:
            completeness = 20
        rating['components']['completeness'] = round(completeness, 2)
        
        # 2. Balance Score (0-20 points)
        imbalance = self.quality_report.get('class_imbalance', {}).get('ratio', 1)
        if imbalance <= 1.5:
            balance = 20
        elif imbalance <= 2:
            balance = 15
        elif imbalance <= 3:
            balance = 10
        else:
            balance = max(0, 10 - (imbalance - 3) * 2)
        rating['components']['balance'] = round(balance, 2)
        
        # 3. Size Score (0-20 points)
        dataset_size = len(self.df)
        if dataset_size >= 50000:
            size_score = 20
        elif dataset_size >= 10000:
            size_score = 15
        elif dataset_size >= 5000:
            size_score = 10
        else:
            size_score = 5
        rating['components']['size'] = size_score
        
        # 4. Feature Quality Score (0-20 points)
        # Based on correlation with target
        if self.feature_stats.get('correlations'):
            corrs = self.feature_stats['correlations'].get('with_malicious', {})
            if corrs:
                avg_abs_corr = np.mean([abs(v) for v in corrs.values()])
                quality_score = min(20, avg_abs_corr * 40)  # Scale to 0-20
            else:
                quality_score = 10
        else:
            quality_score = 10
        rating['components']['feature_quality'] = round(quality_score, 2)
        
        # 5. Consistency Score (0-20 points)
        duplicates_pct = self.quality_report.get('duplicates', {}).get('percentage', 0)
        consistency = max(0, 20 - duplicates_pct * 2)
        rating['components']['consistency'] = round(consistency, 2)
        
        # Calculate overall score
        rating['overall_score'] = round(sum(rating['components'].values()), 2)
        
        # Assign grade
        if rating['overall_score'] >= 90:
            rating['grade'] = 'A+ (Excellent)'
        elif rating['overall_score'] >= 80:
            rating['grade'] = 'A (Very Good)'
        elif rating['overall_score'] >= 70:
            rating['grade'] = 'B (Good)'
        elif rating['overall_score'] >= 60:
            rating['grade'] = 'C (Fair)'
        else:
            rating['grade'] = 'D (Needs Improvement)'
        
        # Generate recommendations
        if rating['components']['completeness'] < 15:
            rating['recommendations'].append("Handle missing data through imputation or removal")
        
        if rating['components']['balance'] < 15:
            rating['recommendations'].append("Apply SMOTE, undersampling, or class weighting for imbalance")
        
        if rating['components']['size'] < 15:
            rating['recommendations'].append("Consider data augmentation or collect more samples")
        
        if rating['components']['feature_quality'] < 15:
            rating['recommendations'].append("Feature engineering needed - create more discriminative features")
        
        if self.quality_report.get('duplicates', {}).get('count', 0) > 0:
            rating['recommendations'].append("Remove duplicate records before training")
        
        print(f"\nRating Components (out of 20 each):")
        for component, score in rating['components'].items():
            print(f"  {component.replace('_', ' ').title()}: {score}/20")
        
        print(f"\nOverall Score: {rating['overall_score']}/100")
        print(f"Grade: {rating['grade']}")
        
        if rating['recommendations']:
            print(f"\nRecommendations:")
            for i, rec in enumerate(rating['recommendations'], 1):
                print(f"  {i}. {rec}")
        
        self.split_recommendations['quality_rating'] = rating
        return rating
    
    def recommend_splits(self):
        """Recommend optimal data splits for cyber ML"""
        print("\n" + "="*80)
        print("10. DATA SPLIT RECOMMENDATIONS")
        print("="*80)
        
        total_samples = len(self.df)
        malicious_count = len(self.df[self.df['label'] == 'malicious'])
        benign_count = len(self.df[self.df['label'] == 'benign'])
        
        splits = {}
        
        # Split 1: Classic 80/20
        splits['80_20'] = {
            'name': '80/20 (Train/Test)',
            'train': {'size': int(total_samples * 0.8), 'percentage': 80},
            'test': {'size': int(total_samples * 0.2), 'percentage': 20},
            'use_case': 'Simple binary classification, quick prototyping',
            'pros': ['Simple', 'Fast training', 'Good for large datasets'],
            'cons': ['No validation set', 'Risk of overfitting'],
            'recommended_for': 'Initial baseline models'
        }
        
        # Split 2: Standard 80/10/10
        splits['80_10_10'] = {
            'name': '80/10/10 (Train/Val/Test)',
            'train': {'size': int(total_samples * 0.8), 'percentage': 80},
            'validation': {'size': int(total_samples * 0.1), 'percentage': 10},
            'test': {'size': int(total_samples * 0.1), 'percentage': 10},
            'use_case': 'Standard ML workflow with hyperparameter tuning',
            'pros': ['Separate validation', 'Good for model selection', 'Prevents overfitting'],
            'cons': ['Smaller test set'],
            'recommended_for': 'Neural networks, deep learning models'
        }
        
        # Split 3: Cyber ML Optimized 70/15/15
        splits['70_15_15'] = {
            'name': '70/15/15 (Train/Val/Test)',
            'train': {'size': int(total_samples * 0.7), 'percentage': 70},
            'validation': {'size': int(total_samples * 0.15), 'percentage': 15},
            'test': {'size': int(total_samples * 0.15), 'percentage': 15},
            'use_case': 'Production WAF with rigorous testing',
            'pros': ['Larger validation/test sets', 'Better generalization assessment', 'Robust evaluation'],
            'cons': ['Less training data'],
            'recommended_for': 'Production WAF systems, safety-critical applications ⭐'
        }
        
        # Split 4: Aggressive 60/20/20
        splits['60_20_20'] = {
            'name': '60/20/20 (Train/Val/Test)',
            'train': {'size': int(total_samples * 0.6), 'percentage': 60},
            'validation': {'size': int(total_samples * 0.2), 'percentage': 20},
            'test': {'size': int(total_samples * 0.2), 'percentage': 20},
            'use_case': 'Highly imbalanced or complex attack patterns',
            'pros': ['Maximum evaluation data', 'Best for detecting rare attacks', 'Robust testing'],
            'cons': ['Limited training data', 'May need data augmentation'],
            'recommended_for': 'Zero-day detection, adversarial robustness testing'
        }
        
        # Split 5: K-Fold Cross-Validation
        k_fold_size = int(total_samples / 5)
        splits['5_fold_cv'] = {
            'name': '5-Fold Cross-Validation',
            'train': {'size': int(total_samples * 0.8), 'percentage': 80},
            'test': {'size': k_fold_size, 'percentage': 20},
            'folds': 5,
            'use_case': 'Maximize data utilization, robust performance estimate',
            'pros': ['Every sample used for training and testing', 'Reduces variance', 'Best performance estimate'],
            'cons': ['Computationally expensive', '5x training time'],
            'recommended_for': 'Small datasets, benchmark comparison'
        }
        
        # Determine best split based on dataset characteristics
        best_split = '70_15_15'  # Default for cyber ML
        
        if total_samples < 10000:
            best_split = '5_fold_cv'
            reason = "Small dataset - cross-validation maximizes data usage"
        elif malicious_count < 1000:
            best_split = '60_20_20'
            reason = "Limited malicious samples - larger test set for robust evaluation"
        elif total_samples > 50000:
            best_split = '80_10_10'
            reason = "Large dataset - standard split provides sufficient samples"
        else:
            best_split = '70_15_15'
            reason = "Medium dataset - balanced split for production WAF"
        
        splits['recommended'] = {
            'split': best_split,
            'reason': reason
        }
        
        print(f"\nDataset Size: {total_samples} samples")
        print(f"  Benign: {benign_count}")
        print(f"  Malicious: {malicious_count}")
        
        print(f"\n{'='*80}")
        print(f"RECOMMENDED SPLIT: {splits[best_split]['name']} ⭐")
        print(f"Reason: {reason}")
        print(f"{'='*80}")
        
        print(f"\nAll Split Options:\n")
        for split_name, split_info in splits.items():
            if split_name == 'recommended':
                continue
            
            marker = " ⭐ RECOMMENDED" if split_name == best_split else ""
            print(f"{split_info['name']}{marker}")
            print(f"  Use Case: {split_info['use_case']}")
            print(f"  Train: {split_info['train']['size']} ({split_info['train']['percentage']}%)")
            if 'validation' in split_info:
                print(f"  Validation: {split_info['validation']['size']} ({split_info['validation']['percentage']}%)")
            print(f"  Test: {split_info['test']['size']} ({split_info['test']['percentage']}%)")
            print(f"  Recommended For: {split_info['recommended_for']}")
            print()
        
        self.split_recommendations['splits'] = splits
        return splits
    
    def create_splits(self):
        """Create actual data splits and save to CSV"""
        print("\n" + "="*80)
        print("11. CREATING DATA SPLITS")
        print("="*80)
        
        from sklearn.model_selection import train_test_split
        
        output_dir = "splits"
        import os
        os.makedirs(output_dir, exist_ok=True)
        
        # Get recommended split
        recommended = self.split_recommendations['splits']['recommended']['split']
        
        splits_to_create = ['80_20', '80_10_10', '70_15_15', '60_20_20']
        
        split_metadata = []
        
        for split_name in splits_to_create:
            split_info = self.split_recommendations['splits'][split_name]
            
            print(f"\nCreating {split_info['name']}...")
            
            # Stratified split
            if 'validation' in split_info:
                # Three-way split
                train_size = split_info['train']['percentage'] / 100
                val_size = split_info['validation']['percentage'] / 100
                test_size = split_info['test']['percentage'] / 100
                
                # First split: train vs (val + test)
                train, temp = train_test_split(
                    self.df, 
                    test_size=(1 - train_size),
                    stratify=self.df['label'],
                    random_state=42
                )
                
                # Second split: val vs test
                val, test = train_test_split(
                    temp,
                    test_size=(test_size / (val_size + test_size)),
                    stratify=temp['label'],
                    random_state=42
                )
                
                # Save splits
                train_path = f"{output_dir}/csic_{split_name}_train.csv"
                val_path = f"{output_dir}/csic_{split_name}_validation.csv"
                test_path = f"{output_dir}/csic_{split_name}_test.csv"
                
                train.to_csv(train_path, index=False)
                val.to_csv(val_path, index=False)
                test.to_csv(test_path, index=False)
                
                print(f"  ✓ Train: {len(train)} samples -> {train_path}")
                print(f"  ✓ Validation: {len(val)} samples -> {val_path}")
                print(f"  ✓ Test: {len(test)} samples -> {test_path}")
                
                # Metadata
                split_metadata.append({
                    'split_name': split_name,
                    'train_size': len(train),
                    'train_benign': len(train[train['label'] == 'benign']),
                    'train_malicious': len(train[train['label'] == 'malicious']),
                    'val_size': len(val),
                    'val_benign': len(val[val['label'] == 'benign']),
                    'val_malicious': len(val[val['label'] == 'malicious']),
                    'test_size': len(test),
                    'test_benign': len(test[test['label'] == 'benign']),
                    'test_malicious': len(test[test['label'] == 'malicious']),
                    'recommended': split_name == recommended
                })
                
            else:
                # Two-way split
                train, test = train_test_split(
                    self.df,
                    test_size=(1 - split_info['train']['percentage'] / 100),
                    stratify=self.df['label'],
                    random_state=42
                )
                
                train_path = f"{output_dir}/csic_{split_name}_train.csv"
                test_path = f"{output_dir}/csic_{split_name}_test.csv"
                
                train.to_csv(train_path, index=False)
                test.to_csv(test_path, index=False)
                
                print(f"  ✓ Train: {len(train)} samples -> {train_path}")
                print(f"  ✓ Test: {len(test)} samples -> {test_path}")
                
                split_metadata.append({
                    'split_name': split_name,
                    'train_size': len(train),
                    'train_benign': len(train[train['label'] == 'benign']),
                    'train_malicious': len(train[train['label'] == 'malicious']),
                    'test_size': len(test),
                    'test_benign': len(test[test['label'] == 'benign']),
                    'test_malicious': len(test[test['label'] == 'malicious']),
                    'recommended': split_name == recommended
                })
        
        # Save metadata
        metadata_df = pd.DataFrame(split_metadata)
        metadata_path = f"{output_dir}/split_metadata.csv"
        metadata_df.to_csv(metadata_path, index=False)
        print(f"\n  ✓ Metadata saved: {metadata_path}")
        
        return output_dir
    
    def generate_report(self):
        """Generate comprehensive JSON report"""
        print("\n" + "="*80)
        print("12. GENERATING COMPREHENSIVE REPORT")
        print("="*80)
        
        # Convert numpy types to native Python types for JSON serialization
        def convert_to_native(obj):
            if isinstance(obj, np.integer):
                return int(obj)
            elif isinstance(obj, np.floating):
                return float(obj)
            elif isinstance(obj, np.ndarray):
                return obj.tolist()
            elif isinstance(obj, np.bool_):
                return bool(obj)
            elif isinstance(obj, dict):
                return {k: convert_to_native(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_to_native(item) for item in obj]
            else:
                return obj
        
        report = {
            'dataset_info': {
                'name': 'CSIC 2010 HTTP Dataset',
                'total_samples': len(self.df),
                'features': list(self.df.columns),
                'target_variable': 'label'
            },
            'statistical_analysis': convert_to_native(self.feature_stats),
            'quality_assessment': convert_to_native(self.quality_report),
            'split_recommendations': convert_to_native(self.split_recommendations)
        }
        
        output_path = "analysis_output/comprehensive_report.json"
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"  ✓ Comprehensive report saved: {output_path}")
        
        return report


def main():
    """Main execution function"""
    print("\n" + "="*80)
    print("CSIC 2010 DATASET - STATE-OF-THE-ART ANALYSIS FOR CYBER ML")
    print("="*80)
    
    analyzer = CSICAnalyzer("csic_database.csv")
    
    # Execute comprehensive analysis pipeline
    analyzer.load_data()
    analyzer.compute_central_tendency()
    analyzer.compute_spread_skewness()
    analyzer.detect_outliers()
    analyzer.analyze_correlations()
    analyzer.analyze_distributions()
    analyzer.assess_data_quality()
    analyzer.detect_bias()
    analyzer.generate_visualizations()
    analyzer.compute_training_rating()
    analyzer.recommend_splits()
    analyzer.create_splits()
    analyzer.generate_report()
    
    print("\n" + "="*80)
    print("✅ ANALYSIS COMPLETE")
    print("="*80)
    print("\nOutputs:")
    print("  📊 Visualizations: analysis_output/")
    print("  📁 Data Splits: splits/")
    print("  📄 JSON Report: analysis_output/comprehensive_report.json")
    print("\n" + "="*80)


if __name__ == "__main__":
    main()
