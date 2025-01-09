from sqlmodel import Field, Session, SQLModel, create_engine, select

from app.appmodels import Hero

hero_1 = Hero(name="Deadpond", secret_name="Dive Wilson")
hero_2 = Hero(name="Spider-Boy", secret_name="Pedro Parqueador")
hero_3 = Hero(name="Rusty-Man", secret_name="Tommy Sharp", age=48)

if __name__ == "__main__":
    print("hello")

    engine = create_engine("sqlite:///data/database.db")
    SQLModel.metadata.create_all(engine)

    with Session(engine) as session:
        session.add(hero_1)
        session.add(hero_2)
        session.add(hero_3)
        session.commit()

    with Session(engine) as session:
        statement = select(Hero).where(Hero.name == "Spider-Boy")
        heroes = session.exec(statement)
        for each in heroes:
            print(each)
        