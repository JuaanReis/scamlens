from pydantic import BaseModel

class ActiveBody(BaseModel):
    is_active: bool

class PlanBody(BaseModel):
    plan_name: str

VALID_PLANS = {"standard", "go_pro", "plus_premium"}