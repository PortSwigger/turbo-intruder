# Turbo Intruder Decorators
## Response Decorators
Turbo Intruder provides the researcher with the power of the entire python language to describe how to issue HTTP Requests and how to handle HTTP responses. However, because the language is very flexible there are certain patterns of code that are often used for various scenarios of response handling. It is a common practice for a user to potentially want to match or filter responses based on various criteria. For example, a user may only want to handle a response based on the response content matching a specific regex or HTTP Status code. Conversely, a user may want to filter out responses based on a specific regex or status code. Each one of these actions requires writing and pasting various `handleResponse` function implementations to meet these desired goals. Tools like `ffuf` and `dirsearch` have easy ways to enable these matchers and filters, Turbo Intruder unfortunately does not and it is left to the user to write these implementations. With this update Turbo Intruder shall contain matcher and filter implementations built-in to the plugin to provide all users the ability to easily add/remove complex matcher and filter logic to their `handleResponse` implementations.
### Example Response Decorator
Let’s say we want to view only responses with status 200 and 204, a user may write an implementation which looks like this:
```python
@MatchStatus(200,204)
def handleResponse(req, interesting):
    table.add(req)
```
Conversely, they may want to view all responses with all other status except for 200 and 204
```python
@FilterStatus(200,204)
def handleResponse(req, interesting):
    table.add(req)
```
Python decorators can stack on top of each other and they get evaluated from top to bottom. Lets go ahead and match all responses status 200 and 204 but only those responses between 100 to 1000 bytes
```python
@MatchStatus(200,204)
@MatchSizeRange(100,1000)
def handleResponse(req, interesting):
    table.add(req)
```

Maybe we want to use regular expressions to help out with some cookie matching
```python
@MatchRegex(r".*Set-Cookie.*")
@MatchRegex(r".*SECRETCOOKIENAME.*")
def handleResponse(req, interesting):
    table.add(req)
```

Or perhaps we want to filter out pesky 200 Not Founds
```python
@MatchStatus(200)
@FilterRegex(r".*Not Found.*")
def handleResponse(req, interesting):
    table.add(req)
```

### Supported Response Decorators
| Decorator | Description |
| --- | --- |
| @MatchStatus(StatusCode, ...) | Matches responses with 1 or more specified status code(s) |
| @FilterStatus(StatusCode, ...) | Filters responses with 1 or more specified status code(s) |
| @MatchSize(RawSize, ...) | Matches responses with 1 or more specified response size(s) |
| @FilterSize(RawSize, ...) | Filters responses with 1 or more specified response size(s) |
| @MatchSizeRange(min, max) | Matches responses whose sizes fall between min and max (inclusive) |
| @FilterSizeRange(min, max) | Filters responses whose sizes fall between min and max (inclusive) |
| @MatchWordCount(WordCount, ...) | Matches responses with 1 or more specified response word count(s) |
| @FilterWordCount(WordCount, ...) | Filters responses with 1 or more specified response word count(s) |
| @MatchWordCountRange(min, max) | Matches responses whose word count fall between min and max (inclusive) |
| @FilterWordCountRange(min, max) | Filters responses whose word count fall between min and max (inclusive) |
| @MatchLineCount(LineCount, ...) | Matches responses with 1 or more specified response line count(s) |
| @FilterLineCount(LineCount, ...) | Filters responses with 1 or more specified response line count(s) |
| @MatchLineCountRange(min, max) | Matches responses whose line count fall between min and max (inclusive) |
| @FilterLineCountRange(min, max) | Filters responses whose line count fall between min and max (inclusive) |
| @MatchRegex(expression) | Matches responses which match the specified regex (case insensitive) |
| @FilterRegex(expression) | Filters responses which match the specified regex (case insensitive) |
| @UniqueSize(instances=1) | Only allows through N instances of responses with a given status/size |
| @UniqueWordCount(instances=1) | Only allows through N instances of responses with a given status/word count |
| @UniqueLineCount(instances=1) | Only allows through N instances of responses with a given status/line count |

### Unique Decorators
Glancing at the table most of the decorators probably seem straight forward. The only decorators that may require a little more explanation are the ones that start with `Unique`. These decorators are useful for fuzzing campaigns against an API or HTTP headers in which the responses stay for the most part static. Unique decorators reduce the signal/noise ratio by keeping a history of keys and only allowing N instances (N=1 by default) of a key to be processed. A key is made up of a status/size, status/word count, and status/line count pair. So for example if we consider the `@UniqueSize(2)` decorator and 1000 responses were received, if 250 of those responses had a status 200 with a size of 270 bytes only the first 2 of the 250 responses would be processed into the `handleResponse` function. If one of the 1000 responses had a status of 200 with a size of 271 that would register into a separate unique key and be processed by `handleResponse`. If you perform fuzzing iterations on JSON structure to post to an endpoint you may use `@UniqueSize()` to catch all unique error messages produced by the endpoint and the decorator will throw away responses associated with duplicate keys.

