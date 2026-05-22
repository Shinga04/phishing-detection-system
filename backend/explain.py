import numpy as np
from lime.lime_tabular import LimeTabularExplainer

from feature_engineering import FEATURE_ORDER


def build_explainer(train_features: np.ndarray) -> LimeTabularExplainer:
    return LimeTabularExplainer(
        training_data=train_features,
        feature_names=FEATURE_ORDER,
        class_names=["safe", "phishing"],
        mode="classification",
    )


def explain_prediction(explainer, model, vector):
    vector = np.asarray(vector)
    data_row = vector[0] if vector.ndim >= 2 else vector
    exp = explainer.explain_instance(
        data_row=data_row,
        predict_fn=model.predict_proba,
        num_features=6,
    )
    return [f"{feature}: {weight:.4f}" for feature, weight in exp.as_list()]
