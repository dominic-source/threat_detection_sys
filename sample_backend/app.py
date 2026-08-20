from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import json

app = FastAPI(title="Minimal Backend")

@app.get("/")
async def root():
    return {"message": "Backend is running", "status": "ok"}

@app.get("/{path:path}")
async def catch_all_get(path: str, request: Request):
    return {
        "path": path,
        "method": "GET",
        "query_params": dict(request.query_params),
        "status": "success",
        "data": None
    }

@app.post("/{path:path}")
async def catch_all_post(path: str, request: Request, body: dict = None):
    return {
        "path": path,
        "method": "POST",
        "query_params": dict(request.query_params),
        "body": body,
        "status": "success"
    }

@app.put("/{path:path}")
async def catch_all_put(path: str, request: Request, body: dict = None):
    return {
        "path": path,
        "method": "PUT",
        "query_params": dict(request.query_params),
        "body": body,
        "status": "success"
    }

@app.delete("/{path:path}")
async def catch_all_delete(path: str, request: Request):
    return {
        "path": path,
        "method": "DELETE",
        "query_params": dict(request.query_params),
        "status": "success"
    }

@app.patch("/{path:path}")
async def catch_all_patch(path: str, request: Request, body: dict = None):
    return {
        "path": path,
        "method": "PATCH",
        "query_params": dict(request.query_params),
        "body": body,
        "status": "success"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=3000)
