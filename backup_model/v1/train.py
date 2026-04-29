"""
Main Training Script for Twilight WAF AI v1
Uses auto-sklearn for automated machine learning
Optimized for: very low latency, very high throughput, very high accuracy
"""

import warnings
from pathlib import Path
from typing import Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedShuffleSplit, train_test_split
from sklearn.utils.class_weight import compute_class_weight

warnings.filterwarnings("ignore")

from attack_labeler import AttackLabeler
from config import (
    LOGS_DIR,
    MODEL_DIR,
    automl_config,
    owasp_config,
    training_config,
)
from evaluation import ModelEvaluator
from feature_extraction import FastFeatureExtractor


class WAFTrainer:
    """
    Main training pipeline for WAF AI model
    """
    
    def __init__(self):
        self.attack_labeler = AttackLabeler()
        self.feature_extractor = FastFeatureExtractor()
        self.evaluator = ModelEvaluator()
        
        self.model = None
        self.X_train = None
        self.X_val = None
        self.X_test = None
        self.y_train = None
        self.y_val = None
        self.y_test = None
        
        self.df = None
        self.attack_types = owasp_config.ATTACK_TYPES
        
    def load_and_prepare_data(self) -> pd.DataFrame:
        """Load and prepare dataset with attack type labels"""
        print("\n" + "=" * 80)
        print("STEP 1: DATA LOADING AND PREPARATION")
        print("=" * 80)
        
        print(f"Loading dataset from {training_config.TRAIN_DATA_PATH}...")
        df = pd.read_csv(training_config.TRAIN_DATA_PATH, low_memory=False)
        print(f"Loaded {len(df)} rows, {len(df.columns)} columns")
        
        # Sample if needed
        if training_config.MAX_SAMPLES is not None and len(df) > training_config.MAX_SAMPLES:
            print(f"Sampling {training_config.MAX_SAMPLES} rows...")
            df = df.sample(n=training_config.MAX_SAMPLES, random_state=training_config.RANDOM_STATE)
        
        # Check for required columns
        if training_config.TEXT_COLUMN not in df.columns:
            raise ValueError(f"Text column '{training_config.TEXT_COLUMN}' not found in dataset")
        if training_config.LABEL_COLUMN not in df.columns:
            raise ValueError(f"Label column '{training_config.LABEL_COLUMN}' not found in dataset")
        
        # Remove missing values
        df = df.dropna(subset=[training_config.TEXT_COLUMN, training_config.LABEL_COLUMN])
        print(f"After removing missing values: {len(df)} rows")
        
        # Label attack types
        print("\nLabeling attack types...")
        df = self.attack_labeler.label_dataset(
            df,
            text_column=training_config.TEXT_COLUMN,
            label_column=training_config.LABEL_COLUMN,
            create_multi_label=False,
        )
        
        print("\nAttack Type Distribution:")
        attack_stats = self.attack_labeler.get_attack_statistics(df)
        print(attack_stats)
        
        # Filter out classes with too few samples
        min_count = training_config.MIN_LABEL_COUNT
        attack_counts = df["attack_label"].value_counts()
        valid_labels = attack_counts[attack_counts >= min_count].index
        df = df[df["attack_label"].isin(valid_labels)]
        print(f"\nAfter filtering classes with < {min_count} samples: {len(df)} rows")
        
        self.df = df
        return df
    
    def create_splits(self) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """Create stratified train/val/test splits"""
        print("\n" + "=" * 80)
        print("STEP 2: CREATING TRAIN/VAL/TEST SPLITS")
        print("=" * 80)
        
        # First split: train+val vs test
        train_val_df, test_df = train_test_split(
            self.df,
            test_size=training_config.TEST_SIZE,
            random_state=training_config.RANDOM_STATE,
            stratify=self.df["attack_label"] if training_config.STRATIFY else None,
        )
        
        # Second split: train vs val
        val_size_adjusted = training_config.VAL_SIZE / (1 - training_config.TEST_SIZE)
        train_df, val_df = train_test_split(
            train_val_df,
            test_size=val_size_adjusted,
            random_state=training_config.RANDOM_STATE,
            stratify=train_val_df["attack_label"] if training_config.STRATIFY else None,
        )
        
        print(f"Train set: {len(train_df)} samples")
        print(f"Val set:   {len(val_df)} samples")
        print(f"Test set:  {len(test_df)} samples")
        
        print("\nTrain set distribution:")
        print(train_df["attack_type"].value_counts())
        
        return train_df, val_df, test_df
    
    def extract_features(
        self,
        train_df: pd.DataFrame,
        val_df: pd.DataFrame,
        test_df: pd.DataFrame,
    ) -> None:
        """Extract features from all splits"""
        print("\n" + "=" * 80)
        print("STEP 3: FEATURE EXTRACTION")
        print("=" * 80)
        
        # Fit on training data
        print("Fitting feature extractor on training data...")
        X_train = self.feature_extractor.fit_transform(
            train_df[training_config.TEXT_COLUMN],
            train_df["attack_label"].values,
        )
        y_train = train_df["attack_label"].values
        
        print(f"Training features shape: {X_train.shape}")
        print(f"Feature sparsity: {1 - X_train.nnz / (X_train.shape[0] * X_train.shape[1]):.2%}")
        
        # Transform validation and test data
        print("\nTransforming validation data...")
        X_val = self.feature_extractor.transform(val_df[training_config.TEXT_COLUMN])
        y_val = val_df["attack_label"].values
        
        print("Transforming test data...")
        X_test = self.feature_extractor.transform(test_df[training_config.TEXT_COLUMN])
        y_test = test_df["attack_label"].values
        
        self.X_train = X_train
        self.X_val = X_val
        self.X_test = X_test
        self.y_train = y_train
        self.y_val = y_val
        self.y_test = y_test
        
        # Save feature extractor
        feature_extractor_path = MODEL_DIR / "feature_extractor.pkl"
        self.feature_extractor.save(str(feature_extractor_path))
        print(f"\n✓ Saved feature extractor to {feature_extractor_path}")
    
    def train_model(self) -> None:
        """Train model using auto-sklearn"""
        print("\n" + "=" * 80)
        print("STEP 4: MODEL TRAINING WITH AUTO-SKLEARN")
        print("=" * 80)
        
        try:
            import autosklearn.classification
        except ImportError:
            print("ERROR: auto-sklearn not installed. Installing fallback (sklearn RandomForest)...")
            print("To use auto-sklearn, install it with: pip install auto-sklearn")
            self._train_fallback_model()
            return
        
        # Compute class weights for imbalanced data
        class_weights = None
        if training_config.BALANCE_CLASSES:
            classes = np.unique(self.y_train)
            weights = compute_class_weight("balanced", classes=classes, y=self.y_train)
            class_weights = {cls: weight for cls, weight in zip(classes, weights)}
            print(f"\nClass weights (for imbalance): {class_weights}")
        
        # Initialize auto-sklearn classifier
        print("\nInitializing auto-sklearn classifier...")
        print(f"  Time budget: {automl_config.TIME_LEFT_FOR_THIS_TASK}s")
        print(f"  Per-run time limit: {automl_config.PER_RUN_TIME_LIMIT}s")
        print(f"  Metric: {automl_config.METRIC}")
        
        self.model = autosklearn.classification.AutoSklearnClassifier(
            time_left_for_this_task=automl_config.TIME_LEFT_FOR_THIS_TASK,
            per_run_time_limit=automl_config.PER_RUN_TIME_LIMIT,
            ensemble_size=automl_config.ENSEMBLE_SIZE,
            ensemble_nbest=automl_config.ENSEMBLE_NBEST,
            n_jobs=automl_config.N_JOBS,
            memory_limit=automl_config.MEMORY_LIMIT,
            resampling_strategy=automl_config.RESAMPLING_STRATEGY,
            resampling_strategy_arguments=automl_config.RESAMPLING_STRATEGY_ARGUMENTS,
            metric=autosklearn.metrics.make_scorer(
                automl_config.METRIC,
                autosklearn.metrics.__dict__[automl_config.METRIC],
            ) if automl_config.METRIC in autosklearn.metrics.__dict__ else None,
            tmp_folder=automl_config.TMP_FOLDER,
            output_folder=automl_config.OUTPUT_FOLDER,
            delete_tmp_folder_after_terminate=automl_config.DELETE_TMP_FOLDER_AFTER_TERMINATE,
            initial_configurations_via_metalearning=automl_config.INITIAL_CONFIGURATIONS_VIA_METALEARNING,
            include_estimators=automl_config.INCLUDE_ESTIMATORS,
            exclude_estimators=automl_config.EXCLUDE_ESTIMATORS,
            include_preprocessors=automl_config.INCLUDE_PREPROCESSORS,
        )
        
        print("\nTraining auto-sklearn model (this may take a while)...")
        print("Auto-sklearn will automatically:")
        print("  1. Select best algorithms")
        print("  2. Tune hyperparameters")
        print("  3. Build an ensemble")
        print("  4. Optimize for the specified metric")
        
        # Train
        self.model.fit(self.X_train, self.y_train)
        
        print("\n✓ Training complete!")
        
        # Show model statistics
        print("\nAuto-sklearn Model Statistics:")
        print(f"  Models evaluated: {len(self.model.cv_results_['mean_test_score'])}")
        print(f"  Best model score: {self.model.cv_results_['mean_test_score'].max():.4f}")
        
        # Save model
        model_path = MODEL_DIR / "waf_model.pkl"
        joblib.dump(self.model, str(model_path))
        print(f"\n✓ Saved model to {model_path}")
    
    def _train_fallback_model(self) -> None:
        """Fallback to sklearn RandomForest if auto-sklearn not available"""
        from sklearn.ensemble import RandomForestClassifier
        
        print("\nTraining fallback model (Random Forest)...")
        
        # Compute class weights
        classes = np.unique(self.y_train)
        weights = compute_class_weight("balanced", classes=classes, y=self.y_train)
        class_weights = {cls: weight for cls, weight in zip(classes, weights)}
        
        self.model = RandomForestClassifier(
            n_estimators=200,
            max_depth=30,
            min_samples_split=5,
            min_samples_leaf=2,
            class_weight=class_weights,
            n_jobs=-1,
            random_state=training_config.RANDOM_STATE,
            verbose=1,
        )
        
        self.model.fit(self.X_train, self.y_train)
        
        print("\n✓ Training complete!")
        
        # Save model
        model_path = MODEL_DIR / "waf_model.pkl"
        joblib.dump(self.model, str(model_path))
        print(f"\n✓ Saved model to {model_path}")
    
    def evaluate_model(self) -> None:
        """Evaluate model on validation and test sets"""
        print("\n" + "=" * 80)
        print("STEP 5: MODEL EVALUATION")
        print("=" * 80)
        
        # Get class names
        inverse_attack_types = {v: k for k, v in self.attack_types.items()}
        unique_labels = np.unique(np.concatenate([self.y_train, self.y_val, self.y_test]))
        class_names = [inverse_attack_types.get(label, f"class_{label}") for label in unique_labels]
        
        # Validation set evaluation
        print("\n📊 VALIDATION SET EVALUATION:")
        print("-" * 80)
        y_val_pred = self.model.predict(self.X_val)
        y_val_proba = self.model.predict_proba(self.X_val) if hasattr(self.model, "predict_proba") else None
        
        val_metrics = self.evaluator.evaluate(
            self.y_val,
            y_val_pred,
            y_val_proba,
            class_names=class_names,
        )
        self.evaluator.print_metrics(val_metrics)
        
        # Test set evaluation
        print("\n\n📊 TEST SET EVALUATION:")
        print("-" * 80)
        y_test_pred = self.model.predict(self.X_test)
        y_test_proba = self.model.predict_proba(self.X_test) if hasattr(self.model, "predict_proba") else None
        
        test_metrics = self.evaluator.evaluate(
            self.y_test,
            y_test_pred,
            y_test_proba,
            class_names=class_names,
        )
        self.evaluator.print_metrics(test_metrics)
        
        # Benchmark latency
        latency_metrics = self.evaluator.benchmark_inference_latency(
            self.model,
            self.X_test[:100],  # Use first 100 samples for latency benchmark
            n_runs=50,
        )
        
        # Save metrics
        metrics_path = LOGS_DIR / f"metrics_{training_config.MODEL_VERSION}.json"
        all_metrics = {
            "validation": val_metrics,
            "test": test_metrics,
            "latency": latency_metrics,
            "model_version": training_config.MODEL_VERSION,
        }
        self.evaluator.save_metrics(all_metrics, str(metrics_path))
        
        # Generate plots
        print("\nGenerating visualizations...")
        
        # Confusion matrix
        cm_path = LOGS_DIR / f"confusion_matrix_{training_config.MODEL_VERSION}.png"
        self.evaluator.plot_confusion_matrix(
            np.array(test_metrics["confusion_matrix"]),
            class_names,
            str(cm_path),
            normalize=True,
        )
        
        # Per-class metrics
        metrics_plot_path = LOGS_DIR / f"per_class_metrics_{training_config.MODEL_VERSION}.png"
        self.evaluator.plot_per_class_metrics(test_metrics, str(metrics_plot_path))
        
        print("\n✓ Evaluation complete!")
    
    def run_full_pipeline(self) -> None:
        """Run the complete training pipeline"""
        print("\n" + "=" * 80)
        print("TWILIGHT WAF AI v1 - FULL TRAINING PIPELINE")
        print("=" * 80)
        print(f"Model Version: {training_config.MODEL_VERSION}")
        print(f"Dataset: {training_config.TRAIN_DATA_PATH}")
        print(f"Output: {MODEL_DIR}")
        print("=" * 80)
        
        # Step 1: Load and prepare data
        self.load_and_prepare_data()
        
        # Step 2: Create splits
        train_df, val_df, test_df = self.create_splits()
        
        # Step 3: Extract features
        self.extract_features(train_df, val_df, test_df)
        
        # Step 4: Train model
        self.train_model()
        
        # Step 5: Evaluate model
        self.evaluate_model()
        
        print("\n" + "=" * 80)
        print("🎉 TRAINING PIPELINE COMPLETE!")
        print("=" * 80)
        print(f"\nModel artifacts saved to: {MODEL_DIR}")
        print(f"Logs and metrics saved to: {LOGS_DIR}")
        print("\nNext steps:")
        print("  1. Review metrics and visualizations")
        print("  2. Test inference engine with: python inference.py")
        print("  3. Deploy model to production")
        print("=" * 80 + "\n")


def main():
    """Main entry point"""
    trainer = WAFTrainer()
    trainer.run_full_pipeline()


if __name__ == "__main__":
    main()
