from . import database_connection

class upateSettings:
    
    def update_api_activate(self, userid):
        db = database_connection.database()
        db.commit_to_database(f"UPDATE auth_user SET is_api = 1 WHERE id = {userid}")
    def update_api_disable(self, userid):
        db = database_connection.database()
        db.commit_to_database(f"UPDATE auth_user SET is_api = 0 WHERE id = {userid}")
    def get_api_option(self, userid):
        db = database_connection.database()
        data = db.commit_to_database_data(f"SELECT is_api FROM auth_user WHERE id = {userid}")
        return data[0][0]
        