"""Quick WebSocket progress test using a minimal contract."""
import asyncio, json, time
import websockets  # type: ignore


CONTRACT = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract WsTest {
    mapping(address => uint256) public balances;
    function deposit() public payable { balances[msg.sender] += msg.value; }
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }
}
"""

job_id = "test-ws-001"
ws_url  = f"ws://localhost:8001/ws/analysis/{job_id}"
api_url = "http://localhost:8001/api/analyze"

progress_log = []

async def run():
    print(f"Connecting WebSocket: {ws_url}")
    try:
        async with websockets.connect(ws_url) as ws:
            print("WS connected — sending analyze request")

            import httpx
            async with httpx.AsyncClient(timeout=120) as client:
                task = asyncio.create_task(
                    client.post(api_url, json={"code": CONTRACT, "job_id": job_id})
                )

                # Collect progress messages until done or timeout
                try:
                    async with asyncio.timeout(120):
                        while True:
                            msg = await ws.recv()
                            data = json.loads(msg)
                            progress_log.append(data)
                            print(f"  [{data['step']:02d}/{data['total']}] {data['percent']:3d}% — {data['message']}")
                            if data.get("status") == "done":
                                print("  ✓ status=done received")
                                break
                except (asyncio.TimeoutError, websockets.exceptions.ConnectionClosed):
                    pass

                resp = await task
                result = resp.json()
                if result.get("status") == "success":
                    print(f"\nAnalysis OK — score={result['data']['securityScore']}")
                else:
                    print(f"\nAnalysis error: {result.get('message')}")

    except Exception as e:
        print(f"WebSocket error: {e}")

    print(f"\nProgress steps received: {len(progress_log)}")
    for p in progress_log:
        print(f"  step {p['step']}/{p['total']}  {p['percent']}%  status={p['status']}")

asyncio.run(run())
