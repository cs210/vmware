from random_forest import RandomForestRegressor


def test_rf():
    rf = RandomForestRegressor('dummy.csv')
    rmse = rf.run()

    avg = sum(rmse)/len(rmse)
    assert(avg < 1)