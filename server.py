from typing import Optional
import redis.asyncio as redis
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel, Field
from uuid import uuid4
import json

app = FastAPI()
r: redis.Redis = None


class Peer(BaseModel):
    public_key: str = Field(min_length=32, max_length=512)
    friendly_name: str = Field(max_length=50)


@app.on_event("startup")
async def startup():
    global r
    r = redis.Redis(host='localhost', port=6379)


@app.post("/peers/register")
async def register(peer: Peer, request: Request):
    peer_id = str(uuid4())

    peer_data = {
        "ip": request.client.host,
        "public_key": peer.public_key,
        "friendly_name": peer.friendly_name
    }

    await r.set(peer_id, json.dumps(peer_data), ex=60*60)

    return {"peer_id": peer_id}


@app.get("/peers/{peer_id}")
async def peers(peer_id: str):
    peer_data = await r.get(peer_id)
    if not peer_data:
        raise HTTPException(status_code=404, detail="Peer not found")

    return json.loads(peer_data)
