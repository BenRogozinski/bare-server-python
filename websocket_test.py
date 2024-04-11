import asyncio
import websockets

async def handle_client(reader, writer):
    request_line = await reader.readline()
    method, path, protocol = request_line.decode().strip().split()
    if method == 'GET' and path == '/websocket':
        await upgrade_to_websocket(reader, writer)
    else:
        writer.write(b'HTTP/1.1 404 Not Found\r\n\r\n')
        writer.close()

async def upgrade_to_websocket(reader, writer):
    # Read the HTTP headers to extract the site to connect to
    headers = {}
    while True:
        line = await reader.readline()
        if line == b'\r\n':
            break
        key, value = line.decode().strip().split(': ', 1)
        headers[key] = value

    # Extract the site to connect to
    site = headers.get('X-Site-To-Connect')

    # Upgrade the connection to WebSocket
    writer.write(b'HTTP/1.1 101 Switching Protocols\r\n')
    writer.write(b'Upgrade: websocket\r\n')
    writer.write(b'Connection: Upgrade\r\n')
    writer.write(b'Sec-WebSocket-Accept: dummy_value\r\n')
    writer.write(b'\r\n')
    await writer.drain()

    try:
        async with websockets.connect(site) as websocket_server:
            while True:
                data = await reader.read(1024)
                if not data:
                    break
                await websocket_server.send(data)
    except websockets.exceptions.ConnectionClosed:
        pass

async def start_proxy_server():
    server = await asyncio.start_server(handle_client, 'localhost', 8080)
    async with server:
        await server.serve_forever()

asyncio.run(start_proxy_server())