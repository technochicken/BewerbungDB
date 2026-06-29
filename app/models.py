from pydantic import BaseModel, Field
from typing import Optional, List
from enum import Enum


class JobStatus(str, Enum):
    new = "new"
    reviewing = "reviewing"
    applied = "applied"
    interview = "interview"
    offer = "offer"
    accepted = "accepted"
    rejected = "rejected"
    closed = "closed"
    irrelevant = "irrelevant"


class JobCreate(BaseModel):
    title: str
    company: Optional[str] = None
    location: Optional[str] = None
    description: Optional[str] = None
    requirements: Optional[str] = None
    salary: Optional[str] = None
    job_type: Optional[str] = None
    url: Optional[str] = None
    check_url: Optional[str] = None
    check_keyword: Optional[str] = None
    html_content: Optional[str] = None
    status: JobStatus = JobStatus.new
    notes: Optional[str] = None
    tags: List[str] = []
    expires_at: Optional[str] = None
    external_id: Optional[str] = None
    contact_first_name: Optional[str] = None
    contact_last_name: Optional[str] = None
    contact_salutation: Optional[str] = None
    contact_title: Optional[str] = None
    contact_email: Optional[str] = None
    contact_street: Optional[str] = None
    contact_street_nr: Optional[str] = None
    contact_plz: Optional[str] = None
    contact_city: Optional[str] = None
    job_name_personalized: Optional[str] = None
    company_floskel: Optional[str] = None
    application_date: Optional[str] = None
    bewerbungstext: Optional[str] = None


class JobUpdate(BaseModel):
    title: Optional[str] = None
    company: Optional[str] = None
    location: Optional[str] = None
    description: Optional[str] = None
    requirements: Optional[str] = None
    salary: Optional[str] = None
    job_type: Optional[str] = None
    url: Optional[str] = None
    check_url: Optional[str] = None
    check_keyword: Optional[str] = None
    html_content: Optional[str] = None
    status: Optional[JobStatus] = None
    notes: Optional[str] = None
    tags: Optional[List[str]] = None
    expires_at: Optional[str] = None
    external_id: Optional[str] = None
    contact_first_name: Optional[str] = None
    contact_last_name: Optional[str] = None
    contact_salutation: Optional[str] = None
    contact_title: Optional[str] = None
    contact_email: Optional[str] = None
    contact_street: Optional[str] = None
    contact_street_nr: Optional[str] = None
    contact_plz: Optional[str] = None
    contact_city: Optional[str] = None
    job_name_personalized: Optional[str] = None
    company_floskel: Optional[str] = None
    application_date: Optional[str] = None
    bewerbungstext: Optional[str] = None


class SearchConfigCreate(BaseModel):
    name: str
    keywords: str
    location: Optional[str] = None
    radius: int = 30
    tags: List[str] = []
    match_words: List[str] = []
    source: str = "arbeitsagentur"
    active: bool = True
    poll_interval: int = 3600
    angebotsart: int = 1
    arbeitszeit: Optional[str] = None


class SearchConfigUpdate(BaseModel):
    name: Optional[str] = None
    keywords: Optional[str] = None
    location: Optional[str] = None
    radius: Optional[int] = None
    tags: Optional[List[str]] = None
    match_words: Optional[List[str]] = None
    active: Optional[bool] = None
    poll_interval: Optional[int] = None
    angebotsart: Optional[int] = None
    arbeitszeit: Optional[str] = None


STATUS_COLORS = {
    "new": "blue",
    "reviewing": "yellow",
    "applied": "purple",
    "interview": "indigo",
    "offer": "teal",
    "accepted": "green",
    "rejected": "red",
    "closed": "gray",
    "irrelevant": "slate",
}

ALL_STATUSES = list(STATUS_COLORS.keys())
