import pytest
from app.scanner.ports_checker import check_ports
from unittest.mock import patch, AsyncMock

@pytest.mark.asyncio
async def test_check_ports():
    with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
        # Mock successful connection for port 80
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()
        mock_conn.return_value = (mock_reader, mock_writer)
        
        results = await check_ports("https://example.com", [80])
        assert 80 in results["details"]["open_ports"]
        
    with patch("asyncio.open_connection", side_effect=OSError("Connection refused")):
        results = await check_ports("https://example.com", [80])
        assert 80 not in results["details"]["open_ports"]
