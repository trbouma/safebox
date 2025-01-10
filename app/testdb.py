from sqlmodel import Field, Session, SQLModel, create_engine, select

from app.appmodels import Hero, RegisteredSafebox



if __name__ == "__main__":
    print("hello")

    engine = create_engine("sqlite:///data/database.db")


    with Session(engine) as session:
        statement = select(RegisteredSafebox)
        safeboxes = session.exec(statement)
        for each in safeboxes:
            print(each)
        