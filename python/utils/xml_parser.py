from lxml import etree

# A05:Security Misconfiguration — XML External Entity (XXE) Injection
# resolve_entities=True allows the parser to follow attacker-supplied SYSTEM/PUBLIC entities

def parse_user_profile(xml_data: str) -> dict:
    parser = etree.XMLParser(resolve_entities=True)
    tree = etree.fromstring(xml_data.encode(), parser)
    return {
        'name':  tree.findtext('name'),
        'email': tree.findtext('email'),
    }
