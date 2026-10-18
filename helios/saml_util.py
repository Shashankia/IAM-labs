"""SAML request and response helpers.

What to remember:
- The app sends a compressed AuthnRequest in the browser address bar.
- The identity provider sends the assertion back as a POST, base64, not compressed.
- This lab does not sign the assertion. A company IdP would, and the app would
  check that signature, the audience, and the expiry before trusting the name.
"""

from __future__ import annotations

import base64
import uuid
import zlib
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from xml.sax.saxutils import escape

SAML_ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
SAML_PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol"
NS = {"saml": SAML_ASSERTION, "samlp": SAML_PROTOCOL}


def _stamp(moment: datetime | None = None) -> str:
    moment = moment or datetime.now(timezone.utc)
    return moment.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def deflate_and_encode(xml: str) -> str:
    compressor = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15)
    raw = compressor.compress(xml.encode("utf-8")) + compressor.flush()
    return base64.b64encode(raw).decode("ascii")


def inflate_request(encoded: str) -> str:
    raw = base64.b64decode(encoded)
    return zlib.decompress(raw, -15).decode("utf-8")


def build_authn_request(issuer: str, acs: str, destination: str) -> tuple[str, str]:
    request_id = "_" + uuid.uuid4().hex
    xml = (
        f'<samlp:AuthnRequest xmlns:samlp="{SAML_PROTOCOL}" '
        f'xmlns:saml="{SAML_ASSERTION}" '
        f'ID="{request_id}" Version="2.0" IssueInstant="{_stamp()}" '
        f'Destination="{escape(destination)}" '
        f'AssertionConsumerServiceURL="{escape(acs)}" '
        f'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">'
        f"<saml:Issuer>{escape(issuer)}</saml:Issuer>"
        f"</samlp:AuthnRequest>"
    )
    return request_id, xml


def parse_authn_request(xml: str) -> dict:
    root = ET.fromstring(xml)
    issuer = root.find("saml:Issuer", NS)
    return {
        "id": root.attrib.get("ID", ""),
        "issuer": issuer.text if issuer is not None and issuer.text else "",
        "acs": root.attrib.get("AssertionConsumerServiceURL", ""),
    }


def build_response(user: dict, issuer: str, audience: str, acs: str, in_response_to: str) -> str:
    now = datetime.now(timezone.utc)
    response_id = "_" + uuid.uuid4().hex
    assertion_id = "_" + uuid.uuid4().hex
    roles = "".join(f"<saml:AttributeValue>{escape(role)}</saml:AttributeValue>" for role in user["roles"])
    groups = "".join(f"<saml:AttributeValue>{escape(group)}</saml:AttributeValue>" for group in user["groups"])
    return (
        f'<samlp:Response xmlns:samlp="{SAML_PROTOCOL}" xmlns:saml="{SAML_ASSERTION}" '
        f'ID="{response_id}" Version="2.0" IssueInstant="{_stamp(now)}" '
        f'Destination="{escape(acs)}" InResponseTo="{escape(in_response_to)}">'
        f"<saml:Issuer>{escape(issuer)}</saml:Issuer>"
        f'<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
        f'<saml:Assertion ID="{assertion_id}" Version="2.0" IssueInstant="{_stamp(now)}">'
        f"<saml:Issuer>{escape(issuer)}</saml:Issuer>"
        f"<saml:Subject>"
        f'<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">{escape(user["username"])}</saml:NameID>'
        f"<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">"
        f'<saml:SubjectConfirmationData NotOnOrAfter="{_stamp(now + timedelta(minutes=3))}" '
        f'Recipient="{escape(acs)}" InResponseTo="{escape(in_response_to)}"/>'
        f"</saml:SubjectConfirmation>"
        f"</saml:Subject>"
        f'<saml:Conditions NotBefore="{_stamp(now - timedelta(seconds=30))}" '
        f'NotOnOrAfter="{_stamp(now + timedelta(minutes=3))}">'
        f"<saml:AudienceRestriction><saml:Audience>{escape(audience)}</saml:Audience></saml:AudienceRestriction>"
        f"</saml:Conditions>"
        f"<saml:AttributeStatement>"
        f'<saml:Attribute Name="email"><saml:AttributeValue>{escape(user["email"])}</saml:AttributeValue></saml:Attribute>'
        f'<saml:Attribute Name="department"><saml:AttributeValue>{escape(user["department"])}</saml:AttributeValue></saml:Attribute>'
        f'<saml:Attribute Name="groups">{groups}</saml:Attribute>'
        f'<saml:Attribute Name="roles">{roles}</saml:Attribute>'
        f"</saml:AttributeStatement>"
        f"</saml:Assertion>"
        f"</samlp:Response>"
    )


def encode_response(xml: str) -> str:
    return base64.b64encode(xml.encode("utf-8")).decode("ascii")


def parse_response(encoded_or_xml: str) -> dict:
    text = encoded_or_xml.strip()
    if not text.startswith("<"):
        text = base64.b64decode(text).decode("utf-8")
    root = ET.fromstring(text)
    issuer = root.find("saml:Issuer", NS)
    status = root.find("samlp:Status/samlp:StatusCode", NS)
    assertion = root.find("saml:Assertion", NS)
    name_id = root.find(".//saml:NameID", NS)
    audience = root.find(".//saml:Audience", NS)
    conditions = root.find(".//saml:Conditions", NS)
    attributes = []
    for attr in root.findall(".//saml:Attribute", NS):
        values = [node.text or "" for node in attr.findall("saml:AttributeValue", NS)]
        attributes.append({"name": attr.attrib.get("Name", ""), "values": values})
    return {
        "xml": text,
        "issuer": issuer.text if issuer is not None else "",
        "status": status.attrib.get("Value", "") if status is not None else "",
        "in_response_to": root.attrib.get("InResponseTo", ""),
        "name_id": name_id.text if name_id is not None else "",
        "audience": audience.text if audience is not None else "",
        "not_before": conditions.attrib.get("NotBefore", "") if conditions is not None else "",
        "not_on_or_after": conditions.attrib.get("NotOnOrAfter", "") if conditions is not None else "",
        "attributes": attributes,
        "signed": assertion is not None and "Signature" in ET.tostring(assertion, encoding="unicode"),
    }
