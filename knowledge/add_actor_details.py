
from common import KNOWLEDGE_DB_PATH, get_connection

EXTRA_INFO = {
    "APT29": {
        "country": "Russia",
        "motivation": "Cyber espionage",
        "notes": "Also known as Cozy Bear, NOBELIUM. Targets governments and defense."
    },
    "APT28": {
        "country": "Russia",
        "motivation": "Cyber espionage",
        "notes": "Also known as Fancy Bear. Targets military and political entities."
    },
    "APT41": {
        "country": "China",
        "motivation": "Cyber espionage",
        "notes": "Also known as Winnti Group. Dual-purpose cyber espionage and cybercrime."
    },
    "Lazarus Group": {
        "country": "North Korea",
        "motivation": "Cybercrime, Cyber espionage",
        "notes": "Also known as Hidden Cobra."
    },
    "Sandworm": {
        "country": "Russia",
        "motivation": "Cyber warfare",
        "notes": "Also known as Voodoo Bear. Associated with GRU."
    },
    "Wizard Spider": {
        "country": "Russia",
        "motivation": "Cybercrime (ransomware)",
        "notes": "Also known as TrickBot operators. Conti, Ryuk ransomware."
    },
}


def add_details():
    conn = get_connection(KNOWLEDGE_DB_PATH)
    try:
        for canonical, info in EXTRA_INFO.items():
            conn.execute(
                """
                UPDATE actors
                SET country = ?, motivation = ?, notes = ?
                WHERE canonical_name = ?
                """,
                (info["country"], info["motivation"], info["notes"], canonical),
            )
        conn.commit()
        print(f"Updated {len(EXTRA_INFO)} actors with extra details.")
    finally:
        conn.close()


if __name__ == "__main__":
    add_details()