class User:
    def __init__(self, userid, username, firstname, lastname):
        self.userid = userid
        self.username = username
        self.firstname = firstname
        self.lastname = lastname
        self.is_authenticated = False
        self.is_active = True
        self.is_anonymous = False
 
    def get_id(self):
        return self.userid
