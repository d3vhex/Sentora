from sanic import Sanic
from sanic.response import json as sjson
from functools import wraps

app = Sanic("repro")

def require_permission(name):
    def deco(fn):
        @wraps(fn)
        async def wrapper(request, *a, **kw):
            return sjson({"blocked": True, "perm": name}, status=403)
        return wrapper
    return deco

@require_permission("admin")          # ABOVE  -> suspected bypass
@app.route("/above")
async def above(request):
    return sjson({"reached_handler": True})

@app.route("/below")
@require_permission("admin")          # BELOW  -> should block
async def below(request):
    return sjson({"reached_handler": True})

if __name__ == "__main__":
    import asyncio
    for path in ("/above", "/below"):
        req, resp = app.test_client.get(path)
        print(path, "->", resp.status, resp.json)
