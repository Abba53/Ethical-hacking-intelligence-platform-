import asyncio

from dotenv import load_dotenv

load_dotenv()

from analysis.ai_analysis import AIAnalyst


async def main():
    ai = AIAnalyst()
    print(f"Provider in use: {ai.provider}")

    result = await ai.analyze_threat(
        target="8.8.8.8",
        threat_score=95,
        severity="CRITICAL",
        ioc_type="ipv4",
        signals={
            "malware": "Cobalt Strike",
            "confidence": 100
        }
    )

    print(result)


if __name__ == "__main__":
    asyncio.run(main())
