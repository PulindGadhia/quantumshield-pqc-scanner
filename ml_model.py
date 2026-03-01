import numpy as np
from sklearn.ensemble import RandomForestRegressor

# dummy training data (simulate TLS features)
X = np.array([
    [1, 2048, 1],  # TLS1.3, RSA 2048, classical
    [0, 1024, 1],  # TLS1.2 weak
    [1, 4096, 0],  # Strong
])

y = np.array([40, 75, 20])  # risk scores

model = RandomForestRegressor()
model.fit(X, y)

def predict_risk(tls13, key_size, classical):
    features = np.array([[tls13, key_size, classical]])
    return float(model.predict(features)[0])