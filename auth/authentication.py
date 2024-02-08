from fastapi import HTTPException, status, Depends, APIRouter, Response
from fastapi.security.oauth2 import OAuth2PasswordRequestForm
from db.database import get_db
from sqlalchemy.orm.session import Session
from db.models import DbUser
from db.hashing import Hash
from auth.oauth2 import create_access_token

router = APIRouter(
    tags=['authentication']
)

@router.post('/login')
def login(response :Response, request: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(DbUser).filter(DbUser.username == request.username).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                detail="Invalid Credentials")
    if not Hash.verify(user.password, request.password):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                detail="Incorrect password")

    access_token = create_access_token(data={"username": user.username})

    # response.set_cookie('access_token', access_token, ACCESS_TOKEN_EXPIRES_IN * 60,
    #                     ACCESS_TOKEN_EXPIRES_IN * 60, '/', None, False, True, 'lax')
    # response.set_cookie('username', user.username,
    #                     REFRESH_TOKEN_EXPIRES_IN * 60, REFRESH_TOKEN_EXPIRES_IN * 60, '/', None, False, True, 'lax')

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user.id,
        "username": user.username
    }