from fastapi import FastAPI

# Create an instance of the FastAPI application
app = FastAPI()

# Define a root endpoint
@app.get("/")
def read_root():
    return {"message": "Welcome to the Safebox app!"}

# Define another example endpoint
@app.get("/.well-known/lnurlp/{name}")
def getname(name: str = None):
    return {"name": name}
