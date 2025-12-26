from src.mitre_mapper import MitreMapper

def test_mitre_mapping_bruteforce():
    mapper = MitreMapper()

    detection = {
        "category": "Brute Force",
        "severity": "medium"

    }

    result = mapper.map_to_mitre(detection)

    assert result["mitre_id"] == "T1110"
    assert result["mitre_name"] == "Brute Force"