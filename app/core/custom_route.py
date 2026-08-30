"""Custom Request and APIRoute for JSON body repair before parsing."""

from fastapi import Request
from fastapi.routing import APIRoute

from app.core.json_body_repair import repair_json_body


class JSONRepairRequest(Request):
    """Custom Request that repairs JSON body before parsing."""

    async def body(self) -> bytes:
        """
        Override body() to repair JSON before returning it.

        This intercepts the raw body before FastAPI's JSON parser sees it,
        repairs any unescaped newlines inside JSON strings, then returns
        the repaired body for normal JSON parsing.

        The repaired body is cached in self._body to ensure consistency
        across multiple calls to request.body() within the same request.
        """
        # Check if we already have a repaired body cached
        if not hasattr(self, "_body"):
            # Get the original body (this will be cached by super().body())
            original_body = await super().body()

            # Repair the body (convert real newlines in strings to escaped newlines)
            repaired_body = repair_json_body(original_body)

            # Cache the repaired body to avoid re-repairing on subsequent calls
            self._body = repaired_body

        return self._body


class JSONRepairRoute(APIRoute):
    """Custom APIRoute that uses JSONRepairRequest for body repair."""

    def get_route_handler(self):
        """
        Override to use JSONRepairRequest instead of standard Request.

        This ensures that the custom request class is used for all requests
        to routes using this custom route class.
        """
        original_route_handler = super().get_route_handler()

        async def custom_route_handler(request: Request) -> object:
            # Replace the request with our custom request
            # This is done by creating a new request with the same scope
            repaired_request = JSONRepairRequest(request.scope, request.receive)

            # Call the original route handler with our custom request
            return await original_route_handler(repaired_request)

        return custom_route_handler
