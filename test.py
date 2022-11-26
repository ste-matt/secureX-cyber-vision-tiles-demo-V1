from marshmallow import INCLUDE, Schema, ValidationError, fields


class DashboardTileSchema(Schema):
    tile_id = fields.String(data_key="tile_id", validate='validate_string', required=True)


db = DashboardTileSchema(Schema)




