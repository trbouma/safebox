from sqlmodel import Field, Session, SQLModel, create_engine, select

from app.appmodels import RegisteredSafebox, CurrencyRate



if __name__ == "__main__":
    print("hello")

    engine = create_engine("sqlite:///data/database.db")
    # SQLModel.metadata.create_all(engine,checkfirst=True)

    satoshi = CurrencyRate(currency_code="SAT", currency_rate=1e8)

    with Session(engine) as session:
        session.add(satoshi)
        session.commit()
        statement = select(CurrencyRate)        
        safeboxes = session.exec(statement)
        for each in safeboxes:
            print(each)
        