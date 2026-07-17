import pandas as pd

LOG_FILE = "logs/batch_evaluation_log.csv"

def analyze():
    df = pd.read_csv(LOG_FILE)
    total = len(df)

    print("=== Overall Summary ===")
    print(f"Total Test Runs: {total}")
    print(f"YAML syntactically valid: {df['yaml_valid'].sum()}/{total} ({df['yaml_valid'].mean()*100:.1f}%)")

    if "version_increased" in df.columns:
        print(f"Version increased: {df['version_increased'].sum()}/{total} ({df['version_increased'].mean()*100:.1f}%)")

    if "matches_fixed_version" in df.columns:
        verifiable = df[df["matches_fixed_version"].isin([True, False, "True", "False"])]
        not_verifiable = df[df["matches_fixed_version"] == "no_fixed_version_available"]

        print("\n=== Verifiability ===")
        print(f"Verifiable (Trivy provided a FixedVersion): {len(verifiable)}/{total}")
        print(f"Not verifiable (no FixedVersion from Trivy): {len(not_verifiable)}/{total}")

        if len(verifiable) > 0:
            match_rate = verifiable["matches_fixed_version"].isin([True, "True"]).mean() * 100
            print(f"\nAmong verifiable cases: Match rate with FixedVersion: {match_rate:.1f}%")
        else:
            print("\nNo verifiable cases available — content correctness cannot be assessed.")

    print("\n=== By Image ===")
    print(df.groupby("image")["yaml_valid"].agg(["count", "mean"]))

if __name__ == "__main__":
    analyze()