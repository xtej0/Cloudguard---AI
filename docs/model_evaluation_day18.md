# Model Evaluation and Tuning (Day 18)

## Baseline Model (Day 17)
- **Model:** Random Forest  
- **Accuracy:** ~52%  
- **Issues:**
  - High confusion across classes  
  - Weak MEDIUM-class precision and recall  
  - Labels were overly ambiguous for effective supervised learning  

## Improvements Applied (Day 18)
- Tuned Random Forest hyperparameters  
- Added `class_weight="balanced"` to address class imbalance  
- Benchmarked performance against Gradient Boosting  
- Updated label assignment using a hybrid approach:
  - Deterministic LOW/HIGH regions  
  - Probabilistic MEDIUM region  

- This approach improved decision boundaries while preserving realistic uncertainty in borderline scenarios.  

## Final Results
- **Random Forest Accuracy:** ~81%  
- **Gradient Boosting Accuracy:** ~80%  
- The tuned Random Forest model was selected as the final model due to its slightly higher accuracy and interpretability.  

## Key Observations
- Significant accuracy improvement over the Day 17 baseline  
- Clearer separation between risk classes  
- Improved MEDIUM-class performance  
- Model effectively captures realistic cybersecurity risk patterns  

## Feature Importance
- network_risk_score  
- attack_path_count  
- exposure_score  
- identity_risk_score  

## Conclusion
- Hybrid labeling improved model learnability without sacrificing realism  
- Final model performance is strong and suitable for deployment-oriented workflows  
- The system is ready for backend integration  