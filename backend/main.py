from fastapi import FastAPI

# Initialize the FastAPI application
app = FastAPI()

# Create a route for the home page ("/") that returns a greeting
@app.get("/")
def read_root():
    return {"message": "Hello from Digital Scam Guardian backend!"}