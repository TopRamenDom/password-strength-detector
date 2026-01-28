from password_strength.checker import score_password

def test_empty_password():
    r = score_password("")
    assert r.score == 0

def test_weak_password():
    r = score_password("hello123")
    assert r.score < 60

def test_strong_password():
    r = score_password("T!m3-Wh4l3__G0ld#9472")
    assert r.score >= 70
