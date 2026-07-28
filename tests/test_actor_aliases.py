from actor_aliases import canonical_actor_name, load_actor_aliases


def test_known_aliases_resolve_to_the_same_canonical_name(mock_knowledge_db):
    """Test that known aliases resolve to the correct canonical name."""
    aliases = load_actor_aliases()
    
    assert canonical_actor_name("APT29", aliases) == "APT29"
    assert canonical_actor_name("Cozy Bear", aliases) == "APT29"
    assert canonical_actor_name("nobelium", aliases) == "APT29"


def test_unknown_actor_is_left_unchanged(mock_knowledge_db):
    """Test that unknown actor names are left unchanged."""
    aliases = load_actor_aliases()
    
    assert canonical_actor_name("Unknown Group", aliases) == "Unknown Group"