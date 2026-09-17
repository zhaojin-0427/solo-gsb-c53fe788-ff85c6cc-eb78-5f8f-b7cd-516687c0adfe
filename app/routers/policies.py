"""Policy management endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..db import get_db
from ..schemas import DraftUpdate, PolicyCreate, PublishRequest, rules_to_raw
from ..services import policies as policy_service

router = APIRouter(prefix="/v1/policies", tags=["policies"])


def _policy_summary(p) -> dict:
    return {
        "name": p.name,
        "revision": p.revision,
        "created_at": p.created_at.isoformat() if p.created_at else None,
        "updated_at": p.updated_at.isoformat() if p.updated_at else None,
    }


@router.post("", status_code=201)
def create_policy(body: PolicyCreate, db: Session = Depends(get_db)):
    policy = policy_service.create_policy(db, body.name, rules_to_raw(body.rules))
    out = _policy_summary(policy)
    out["draft_rules"] = policy.draft_rules
    return out


@router.get("")
def list_policies(db: Session = Depends(get_db)):
    return {"policies": [_policy_summary(p) for p in policy_service.list_policies(db)]}


@router.get("/{name}")
def get_policy(name: str, db: Session = Depends(get_db)):
    policy = policy_service.get_policy_or_404(db, name)
    versions = policy_service.list_versions(db, policy)
    out = _policy_summary(policy)
    out["draft_rules"] = policy.draft_rules
    out["published_versions"] = [v.version for v in versions]
    return out


@router.put("/{name}/draft")
def update_draft(name: str, body: DraftUpdate, db: Session = Depends(get_db)):
    policy = policy_service.get_policy_or_404(db, name)
    policy = policy_service.update_draft(db, policy, rules_to_raw(body.rules))
    return {
        "name": policy.name,
        "revision": policy.revision,
        "draft_rules": policy.draft_rules,
    }


@router.post("/{name}/publish", status_code=201)
def publish(name: str, body: PublishRequest, db: Session = Depends(get_db)):
    policy = policy_service.get_policy_or_404(db, name)
    version = policy_service.publish(db, policy, body.expected_revision)
    return {
        "name": policy.name,
        "version": version.version,
        "revision": version.version,
        "created_at": version.created_at.isoformat() if version.created_at else None,
    }


@router.get("/{name}/versions")
def list_versions(name: str, db: Session = Depends(get_db)):
    policy = policy_service.get_policy_or_404(db, name)
    return {
        "name": policy.name,
        "versions": [
            {
                "version": v.version,
                "rule_count": len(v.rules),
                "created_at": v.created_at.isoformat() if v.created_at else None,
            }
            for v in policy_service.list_versions(db, policy)
        ],
    }


@router.get("/{name}/versions/{version}")
def get_version(name: str, version: int, db: Session = Depends(get_db)):
    policy = policy_service.get_policy_or_404(db, name)
    pv = policy_service.get_version_or_404(db, policy, version)
    return {
        "name": policy.name,
        "version": pv.version,
        "rules": pv.rules,
        "created_at": pv.created_at.isoformat() if pv.created_at else None,
    }
