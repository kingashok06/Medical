from pydantic import BaseModel,UUID4
from typing import List





# class Member(BaseModel):
#     member_name: str


class RequestGroup(BaseModel):
    group_name: str
    add_members: List[str]


class Group(BaseModel): 
    group_name:str
    member_name:str

