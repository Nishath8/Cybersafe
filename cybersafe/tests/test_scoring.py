from app.utils.scoring import calculate_score

def test_calculate_score():
    results = {
        "tls": {"score": 100},
        "headers": {"score": 100},
        "cors": {"score": 100},
        "methods": {"score": 100},
        "ports": {"score": 100}
    }
    assert calculate_score(results) == 100
    
    results["tls"]["score"] = 0
    # Weighted: 0*30 + 100*30 + 100*15 + 100*15 + 100*10 = 0 + 3000 + 1500 + 1500 + 1000 = 7000 / 100 = 70
    assert calculate_score(results) == 70
