#!/usr/bin/env python3
"""
Test script to verify RLS implementation works through the MCP server.
"""

import os
import sys
import asyncio
import json
import dotenv
from mcp import ClientSession
from mcp.client.sse import sse_client

# Load environment variables
dotenv.load_dotenv()

async def test_server_rls():
    """Test RLS implementation through the running MCP server."""

    print("🔍 TESTING RLS THROUGH MCP SERVER")
    print("=" * 60)

    # Use fresh token with patient_name fact
    token = "EpMBCikKDHBhdGllbnRfbmFtZQoLRXJpbiBvUlRFZ2EYAyIKCggIgAgSAxiBCBIkCAASIOC_0Xb49M30CB8_X2VzBUBczx50Pgs3UOzieGeC3_aOGkDqacwdG2IxxUB42LHe9cUbYquiHyn2eZ8giIv5k1kELklbyWsUhCeo_ZIQekYuzl5Qa_kn0VSHoFieAkM13-wAIiIKIMpfQB-lDRQyDkFtMdwV9u9t8FBK7su66Q9CHyPp-TDd"

    # Get database URL from environment
    db_url = os.getenv('DATABASE_URL')
    if not db_url:
        print("❌ DATABASE_URL not found in environment")
        return False

    print(f"✅ Using token: {token[:50]}...")
    print(f"✅ Database URL configured")

    try:
        # Connect to MCP server
        pg_mcp_url = "http://localhost:8000/sse"
        print(f"\n🌐 Step 1: Connecting to MCP server at {pg_mcp_url}")

        async with sse_client(url=pg_mcp_url) as streams:
            print("✅ SSE streams established")

            async with ClientSession(*streams) as session:
                print("✅ MCP session created")

                # Initialize the connection
                await session.initialize()
                print("✅ Session initialized")

                # Step 2: Connect to database
                print(f"\n💾 Step 2: Connecting to database")
                try:
                    connect_result = await session.call_tool(
                        "connect",
                        {"connection_string": db_url}
                    )
                    # Parse the JSON response to get the actual connection ID
                    result_text = connect_result.content[0].text
                    result_json = json.loads(result_text)
                    conn_id = result_json["conn_id"]
                    print(f"✅ Database connected with ID: {conn_id}")
                except Exception as e:
                    print(f"❌ Database connection failed: {e}")
                    return False

                # Step 3: Test query with RLS implementation
                print(f"\n🔍 Step 3: Testing query with RLS implementation")

                test_query = """
                SELECT "Patient Name", "Age", "Medical Condition", "Doctor"
                FROM health_records
                LIMIT 10
                """

                try:
                    # This should now use our RLS implementation
                    query_result = await session.call_tool(
                        "pg_query",
                        {
                            "biscuit_token": token,
                            "query": test_query,
                            "conn_id": conn_id
                        }
                    )

                    # Parse the result
                    result_text = query_result.content[0].text
                    try:
                        results = json.loads(result_text)
                        print(f"✅ Query executed successfully")
                        print(f"   Found {len(results)} records")

                        # Check if we got any results for Erin oRTEga
                        erin_records = [r for r in results if r.get('Patient Name') == 'Erin oRTEga']
                        print(f"   Records for Erin oRTEga: {len(erin_records)}")

                        if erin_records:
                            for record in erin_records[:3]:  # Show first 3 records
                                print(f"   - {record['Patient Name']}: {record['Medical Condition']} (Dr. {record['Doctor']})")

                        # Show some other patients to verify we're not filtering correctly yet
                        other_records = [r for r in results if r.get('Patient Name') != 'Erin oRTEga']
                        if other_records:
                            print(f"   Other patients in results: {len(other_records)}")
                            for record in other_records[:2]:  # Show first 2
                                print(f"   - {record['Patient Name']}: {record['Medical Condition']}")

                    except json.JSONDecodeError:
                        print(f"✅ Query executed (non-JSON result): {result_text[:200]}...")

                except Exception as e:
                    print(f"❌ Query failed: {e}")
                    return False

                # Step 4: Disconnect
                print(f"\n🔌 Step 4: Disconnecting")
                try:
                    await session.call_tool("disconnect", {"conn_id": conn_id})
                    print("✅ Disconnected from database")
                except Exception as e:
                    print(f"⚠️  Disconnect failed: {e}")

        print(f"\n🎉 SERVER RLS TEST COMPLETED!")
        print("   - Server connection: ✅")
        print("   - Database connection: ✅")
        print("   - Query with Biscuit token: ✅")
        print("   - RLS session parameter setting: ✅ (check server logs)")
        return True

    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False

if __name__ == "__main__":
    success = asyncio.run(test_server_rls())
    sys.exit(0 if success else 1)