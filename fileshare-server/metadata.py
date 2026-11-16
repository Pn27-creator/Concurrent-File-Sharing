"""File metadata and authorization: *what may this user do with this file?*

The bytes of every file live in data/blobs/<random id>.  Everything we *know
about* a file -- name, size, owner, upload time, checksum, who may read it --
lives separately in data/metadata.json.  Listing files or checking permissions
therefore never has to touch (or read) the file contents.

A file is addressed as  owner/name  (e.g. alice/report.pdf), so two users may
upload files with the same name without clashing.

Access rules for DOWNLOAD (checked on the server, for every request):
    owner of the file ........................ allowed
    user with the "admin" role ............... allowed
    file visibility is "public" .............. allowed
    user is in the file's shared_with list ... allowed
    anyone else .............................. denied (ACCESS_DENIED)
Only the owner (or an admin) may share, change visibility, or delete.
"""

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path


class RequestError(Exception):
    """A problem with one request.  The message is sent to the client and the
    session stays open (nothing is wrong with the connection itself)."""

    def __init__(self, message, code="ERROR"):
        super().__init__(message)
        self.code = code


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def make_ref(owner, name):
    return f"{owner}/{name}"


class MetadataStore:
    def __init__(self, path):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._files = {}      # "owner/name" -> record
        self._pending = set() # refs currently being uploaded
        self._active = {}     # file id -> number of downloads in progress
        self._load()

    # -- persistence -----------------------------------------------------
    def _load(self):
        if self.path.exists():
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self._files = data.get("files", {})

    def _save(self):
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"files": self._files}, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)     # atomic: never a half-written file

    # -- authorization ---------------------------------------------------
    @staticmethod
    def access_level(user, role, rec):
        """Why this user may read the file ('owner', 'admin', 'shared',
        'public'), or None if they may not."""
        if rec["owner"] == user:
            return "owner"
        if role == "admin":
            return "admin"
        if user in rec["shared_with"]:
            return "shared"
        if rec["visibility"] == "public":
            return "public"
        return None

    @staticmethod
    def can_manage(user, role, rec):
        return rec["owner"] == user or role == "admin"

    # -- helpers (call with the lock held) ---------------------------------
    def _must_get(self, owner, name):
        rec = self._files.get(make_ref(owner, name))
        if rec is None:
            raise RequestError("File not found", "NOT_FOUND")
        return rec

    def _must_manage(self, user, role, owner, name):
        rec = self._must_get(owner, name)
        if not self.can_manage(user, role, rec):
            raise RequestError(
                "Access denied: only the owner can change this file", "ACCESS_DENIED")
        return rec

    # -- upload ----------------------------------------------------------
    def reserve(self, owner, name):
        """Claim owner/name before receiving bytes, so two simultaneous
        uploads of the same name cannot both succeed."""
        ref = make_ref(owner, name)
        with self._lock:
            if ref in self._files or ref in self._pending:
                raise RequestError(f"{ref} already exists on the server", "EXISTS")
            self._pending.add(ref)

    def release(self, owner, name):
        with self._lock:
            self._pending.discard(make_ref(owner, name))

    def commit(self, owner, name, file_id, size, sha256, visibility):
        ref = make_ref(owner, name)
        rec = {
            "id": file_id, "name": name, "owner": owner, "size": size,
            "sha256": sha256, "uploaded_at": now_iso(),
            "visibility": visibility, "shared_with": [], "downloads": 0,
        }
        with self._lock:
            self._files[ref] = rec
            self._pending.discard(ref)
            self._save()
            return dict(rec)

    # -- download --------------------------------------------------------
    def begin_download(self, user, role, owner, name):
        """Authorization check for a download.  Returns (record, why) and marks
        the file 'in use' until end_download() is called."""
        with self._lock:
            rec = self._must_get(owner, name)
            why = self.access_level(user, role, rec)
            if why is None:
                raise RequestError(
                    f"Access denied: you may not download {make_ref(owner, name)}",
                    "ACCESS_DENIED")
            self._active[rec["id"]] = self._active.get(rec["id"], 0) + 1
            return dict(rec), why

    def end_download(self, file_id, completed):
        with self._lock:
            left = self._active.get(file_id, 0) - 1
            if left > 0:
                self._active[file_id] = left
            else:
                self._active.pop(file_id, None)
            if completed:
                for rec in self._files.values():
                    if rec["id"] == file_id:
                        rec["downloads"] += 1
                        self._save()
                        break

    # -- listing / info --------------------------------------------------
    def list_visible(self, user, role):
        """Only files this user may read (their own, shared, public, or all
        for an admin).  Share lists are shown to owners/admins only."""
        out = []
        with self._lock:
            for ref, rec in sorted(self._files.items()):
                why = self.access_level(user, role, rec)
                if why is None:
                    continue
                item = {
                    "ref": ref, "name": rec["name"], "owner": rec["owner"],
                    "size": rec["size"], "uploaded_at": rec["uploaded_at"],
                    "visibility": rec["visibility"], "access": why,
                    "downloads": rec["downloads"],
                }
                if self.can_manage(user, role, rec):
                    item["shared_with"] = list(rec["shared_with"])
                out.append(item)
        return out

    def info(self, user, role, owner, name):
        with self._lock:
            rec = self._must_get(owner, name)
            why = self.access_level(user, role, rec)
            if why is None:
                raise RequestError(
                    f"Access denied: you may not view {make_ref(owner, name)}",
                    "ACCESS_DENIED")
            item = dict(rec)
            item["ref"] = make_ref(owner, name)
            item["access"] = why
            if not self.can_manage(user, role, rec):
                item.pop("shared_with", None)
            return item

    # -- managing --------------------------------------------------------
    def set_visibility(self, user, role, owner, name, visibility):
        if visibility not in ("public", "private"):
            raise RequestError("Visibility must be 'public' or 'private'")
        with self._lock:
            rec = self._must_manage(user, role, owner, name)
            rec["visibility"] = visibility
            self._save()

    def share(self, user, role, owner, name, target):
        with self._lock:
            rec = self._must_manage(user, role, owner, name)
            if target == rec["owner"]:
                raise RequestError("The owner already has access")
            if target not in rec["shared_with"]:
                rec["shared_with"].append(target)
                rec["shared_with"].sort()
                self._save()

    def unshare(self, user, role, owner, name, target):
        with self._lock:
            rec = self._must_manage(user, role, owner, name)
            if target in rec["shared_with"]:
                rec["shared_with"].remove(target)
                self._save()

    def delete(self, user, role, owner, name):
        """Remove the record and return the blob id (caller deletes the bytes)."""
        with self._lock:
            rec = self._must_manage(user, role, owner, name)
            if self._active.get(rec["id"]):
                raise RequestError("File is being downloaded right now; try again shortly", "BUSY")
            del self._files[make_ref(owner, name)]
            self._save()
            return rec["id"]

    def count(self):
        with self._lock:
            return len(self._files)
