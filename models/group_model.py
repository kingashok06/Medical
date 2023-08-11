from pydantic import BaseModel
from typing import List



class Group(BaseModel):
    group_name: str
    
    add_members: List[str]

class Member(BaseModel): 
    member_name:str

