# Development Best Practices

## AI Best Practices
- Always check `ai.isEnabled()` before using AI features
- Escape AI-generated content before displaying to users
- Send only essential data to minimize AI credit usage
- Use structured formats (JSON) for AI requests
- Implement response caching for repeated queries
- Use background threads for AI operations