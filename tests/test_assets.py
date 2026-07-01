"""Tests fuer den Asset-Graph."""

from __future__ import annotations

from specter.assets import AssetGraph


def test_add_asset_and_dedup():
    g = AssetGraph()
    a, new1 = g.add_asset("host", "127.0.0.1")
    _, new2 = g.add_asset("host", "127.0.0.1")
    assert new1 is True and new2 is False
    assert len(g) == 1
    assert a.type_label == "Host/IP"


def test_unknown_type_falls_back_to_host():
    g = AssetGraph()
    a, _ = g.add_asset("quatsch", "x")
    assert a.type == "host"


def test_metadata_merges():
    g = AssetGraph()
    g.add_asset("host", "h", note="a")
    a, _ = g.add_asset("host", "h", extra="b")
    assert a.metadata == {"note": "a", "extra": "b"}


def test_edges_and_neighbors():
    g = AssetGraph()
    g.add_asset("host", "h")
    g.add_asset("service", "ssh")
    assert g.add_edge("host:h", "service:ssh", "betreibt") is True
    # Duplikat wird nicht doppelt erfasst.
    assert g.add_edge("host:h", "service:ssh", "betreibt") is False
    # Kante zu unbekanntem Asset schlaegt fehl.
    assert g.add_edge("host:h", "host:unknown", "x") is False
    neigh = g.neighbors("host:h")
    assert ("service:ssh", "betreibt") in neigh
    assert g.neighbors("service:ssh") == [("host:h", "betreibt")]


def test_counts_and_listing():
    g = AssetGraph()
    g.add_asset("host", "h1")
    g.add_asset("host", "h2")
    g.add_asset("secret", "token")
    counts = g.counts_by_type()
    assert counts["Host/IP"] == 2
    assert counts["Geheimnis (Credential/Token)"] == 1
    assert len(g.assets()) == 3
    assert g.get("host:h1") is not None
    assert g.get("host:nope") is None


def test_asset_to_dict():
    g = AssetGraph()
    a, _ = g.add_asset("endpoint", "http://x/api", note="n")
    d = a.to_dict()
    assert d["type"] == "endpoint"
    assert d["type_label"] == "Web-/API-Endpunkt"
    assert d["metadata"]["note"] == "n"
