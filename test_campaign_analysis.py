import asyncio

from dotenv import load_dotenv

load_dotenv(
    "/data/data/com.termux/files/home/ethical-hacking-intel-platform/.env"
)

from analysis.ai_analysis import AIAnalyst


async def main():
    ai = AIAnalyst()

    print("=" * 60)
    print("CAMPAIGN ANALYSIS TEST")
    print("=" * 60)

    print("Provider:", ai.provider)

    result = await ai.analyze_campaign(
        campaign={
            "campaign_id": "TEST-CAMPAIGN-001",
            "indicators": [
                "203.0.113.50",
                "malicious-example.test",
            ],
            "malware": [
                "ExampleMalware",
            ],
            "observed_tactics": [
                "Command and Control",
            ],
            "mitre_attack": [
                "T1071",
            ],
            "targeted_sector": "Technology",
            "targeted_region": "Unknown",
            "source": "test_fixture",
        }
    )

    print("\nResult:")
    print(result)

    assert result.success is True
    assert result.provider == ai.provider.provider_name
    assert result.report_type == "campaign"
    assert result.analysis is not None
    assert result.raw_response
    assert result.execution_time_ms >= 0

    print("\n[PASS] campaign analysis")
    print("[PASS] report type")
    print("[PASS] structured analysis")
    print("[PASS] raw response")
    print("[PASS] execution time")


if __name__ == "__main__":
    asyncio.run(main())
