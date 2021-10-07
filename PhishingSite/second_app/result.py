def prediction_model(url):
    import pickle
    x = [[url]]
    randomforest = pickle.load(open('custom_rf_classifier.sav','rb'))
    prediction = randomforest.predict(x)
    return prediction
