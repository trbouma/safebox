from fastapi import FastAPI

# Create an instance of the FastAPI application
app = FastAPI()

# Define a root endpoint
@app.get("/")
def read_root():
    return {"message": "Welcome to the Safebox app!"}

# Define another example endpoint
@app.get("/.well-known/lnurlp/{name}")
def ln_resolve(name: str = None):

    ln_response = {     "callback": f"https://example.com/{name}",
                        "minSendable": 0,
                        "maxSendable": 210000,
                        "metadata": {},
                        "commentAllowed": 60,
                        "tag": "payRequest"
                   

    }
    return ln_response
