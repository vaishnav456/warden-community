"""Encrypted helpdesk forms and ticket views shared by browser and device APIs."""
import json
import re
import uuid
from flask import abort
import db
from services import support_workflow as workflow

DEFAULT_FORM = dict(categories=["General", "Software", "Network", "Hardware", "Account access"],
                    fields=[])
PRIORITIES = ("low", "normal", "high", "urgent")


def identifier(value):
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        raise ValueError("Invalid ticket or message identifier.")


def short(value, limit=160):
    if not isinstance(value, str):
        raise ValueError("Enter text.")
    value = value.strip()
    if not value or len(value) > limit or any(ord(c) < 32 for c in value):
        raise ValueError("Invalid or overly long text.")
    return value


def form_definition(value):
    if not isinstance(value, dict) or set(value)-{"categories", "fields"}:
        raise ValueError("Use categories and fields only.")
    categories = value.get("categories", DEFAULT_FORM["categories"])
    fields = value.get("fields", [])
    if not isinstance(categories, list) or not 1 <= len(categories) <= 12:
        raise ValueError("Supply 1–12 categories.")
    categories = [short(c, 50) for c in categories]
    if len(set(c.casefold() for c in categories)) != len(categories):
        raise ValueError("Categories must be unique.")
    if not isinstance(fields, list) or len(fields) > 8:
        raise ValueError("At most eight custom fields are allowed.")
    cleaned, seen = [], set()
    for field in fields:
        if not isinstance(field, dict) or set(field)-{"id", "label", "required", "type", "options", "show_if"}:
            raise ValueError("Invalid field definition.")
        key = field.get("id", "")
        if not isinstance(key, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", key) or key in seen:
            raise ValueError("Use unique lowercase field IDs.")
        kind = field.get("type", "text")
        if kind not in ("text", "select") or not isinstance(field.get("required", False), bool):
            raise ValueError("Fields support text or select, with a boolean required flag.")
        item = dict(id=key, label=short(field.get("label"), 80), type=kind, required=field.get("required", False))
        if kind == "select":
            options = field.get("options")
            if not isinstance(options, list) or not 1 <= len(options) <= 10:
                raise ValueError("Select fields need 1–10 options.")
            item["options"] = [short(option, 80) for option in options]
            if len(set(item["options"])) != len(item["options"]):
                raise ValueError("Options must be unique.")
        condition=field.get("show_if")
        if condition is not None:
            if not isinstance(condition,dict) or set(condition)-{"mode","rules"} or condition.get("mode") not in ("all","any"):
                raise ValueError("Choose all or any visibility conditions.")
            rules=condition.get("rules")
            if not isinstance(rules,list) or not 1<=len(rules)<=4:
                raise ValueError("Use one to four visibility conditions.")
            checked=[]
            for rule in rules:
                if not isinstance(rule,dict) or set(rule)-{"source","field","operator","value"}:
                    raise ValueError("Invalid visibility condition.")
                source=rule.get("source")
                operator=rule.get("operator")
                value=rule.get("value")
                if source not in ("field","category","priority","branch") or operator not in ("equals","not_equals"):
                    raise ValueError("Use equals or does not equal.")
                value=short(value,500)
                safe=dict(source=source,operator=operator,value=value)
                if source=="field":
                    dependency=rule.get("field")
                    if dependency not in seen:
                        raise ValueError("Conditions may reference earlier questions only. Reorder questions first.")
                    previous=next(f for f in cleaned if f["id"]==dependency)
                    if previous["type"]=="select" and value not in previous["options"]:
                        raise ValueError("Condition value must match an answer choice.")
                    safe["field"]=dependency
                elif source=="category" and value not in categories:
                    raise ValueError("Condition must match a category.")
                elif source=="priority" and value not in PRIORITIES:
                    raise ValueError("Condition must match a priority.")
                elif source=="branch":
                    safe["value"]=identifier(value)
                checked.append(safe)
            item["show_if"]=dict(mode=condition["mode"],rules=checked)
        cleaned.append(item)
        seen.add(key)
    return dict(categories=categories, fields=cleaned)


def load_form(company):
    rows = db._get(f"support_forms?company_id=eq.{db._q(company['id'])}&limit=1")
    if not rows:
        return dict(categories=list(DEFAULT_FORM["categories"]), fields=[])
    value = db.decrypt_field(company, rows[0]["definition_encrypted"], "support.form")
    return form_definition(value)


def visible(field, answers, context):
    condition=field.get("show_if")
    if not condition:return True
    outcomes=[]
    for rule in condition["rules"]:
        actual=answers.get(rule.get("field"),"") if rule["source"]=="field" else context.get(rule["source"],"")
        matches=str(actual or "")==rule["value"]
        outcomes.append(matches if rule["operator"]=="equals" else not matches)
    return all(outcomes) if condition["mode"]=="all" else any(outcomes)


def ticket_content(body, definition, username, branch_id=None):
    message = workflow.text(body.get("message"))
    subject = short(body.get("subject") or message.splitlines()[0][:120], 160)
    category = body.get("category") or definition["categories"][0]
    priority = body.get("priority") or "normal"
    if category not in definition["categories"] or priority not in PRIORITIES:
        raise ValueError("Choose a valid category and priority.")
    values = body.get("fields", {})
    if not isinstance(values, dict) or set(values)-{f["id"] for f in definition["fields"]}:
        raise ValueError("The form changed. Reload it and try again.")
    fields,answers = {},{}
    context=dict(category=category,priority=priority,branch=str(branch_id or ""))
    for field in definition["fields"]:
        if not visible(field,answers,context):continue
        value = values.get(field["id"], "")
        if not isinstance(value, str) or len(value) > 500 or any(ord(c)<32 for c in value):
            raise ValueError("Invalid custom field value.")
        value = value.strip()
        if field["required"] and not value:
            raise ValueError(field["label"] + " is required.")
        if value and field["type"] == "select" and value not in field["options"]:
            raise ValueError("Choose a valid value for " + field["label"] + ".")
        fields[field["id"]] = dict(label=field["label"], value=value)
        answers[field["id"]]=value
    return dict(username=username, subject=subject, category=category, priority=priority,
                message=message, fields=fields)


def action(company, endpoint, ticket_id, kind, *, admin=None, username=None,
           body=None, message_id=None, assignee=None, visit=None):
    values = dict(p_company=str(company["id"]), p_endpoint=str(endpoint["id"]),
                  p_request=identifier(ticket_id), p_action=kind,
                  p_admin=str(admin["id"]) if admin else None,
                  p_requester=workflow.requester_key(username) if username else None,
                  p_cipher=db.encrypt_field(company, body, "support.request" if kind=="create" else "support.message") if body else None,
                  p_assignee=identifier(message_id or assignee) if (message_id or assignee) else None,
                  p_visit=visit)
    result = db._rpc("support_ticket_action", values)
    if not isinstance(result, dict):
        raise RuntimeError("Ticket state could not be confirmed.")
    return result


def hydrate(row, company, endpoint, include_messages=False, page=0):
    row = dict(row)
    row["request"] = db.decrypt_field(company, row.pop("request_encrypted", None), "support.request") or {}
    row["endpoint"] = endpoint
    row["triage"] = workflow.triage(endpoint)
    row["number"] = str(row["id"])[:8].upper()
    if include_messages:
        messages = db._get(f"support_messages?request_id=eq.{db._q(row['id'])}&company_id=eq.{db._q(company['id'])}&order=created_at.desc,id.desc&limit=51&offset={page*50}")
        row["message_page"] = page
        row["has_older_messages"] = len(messages) > 50
        row["messages"] = [dict(id=m["id"], created_at=m["created_at"],
            body=db.decrypt_field(company, m["message_encrypted"], "support.message") or {})
            for m in reversed(messages[:50])]
    return row


def http_error(result):
    if result.get("error"):
        error = result["error"]
        abort(404 if error=="not_found" else 403 if error=="forbidden" else 409,
              "Ticket changed or cannot accept this action. Refresh and try again.")
