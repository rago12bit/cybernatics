"""core/codeintel/go_lang.py: symbols, calls and entrypoints via tree-sitter-go (plan §20.2)."""

from __future__ import annotations

from core.codeintel.go_lang import extract


def test_function_and_method_become_symbols_with_receiver_qualified_names() -> None:
    src = b"""
package main
func plain() {}

type Server struct{}
func (s *Server) Handle() {}
func (s Server) ByValue() {}
"""
    u = extract("main.go", src)
    by_name = {s.qualified_name: s for s in u.symbols}
    assert by_name["plain"].kind == "function"
    assert by_name["Server.Handle"].kind == "method"
    assert by_name["Server.ByValue"].kind == "method"  # value receiver, not just pointer receiver


def test_calls_are_attributed_to_the_enclosing_function() -> None:
    src = b"""
package main
func caller() { helper() }
func helper() {}
"""
    u = extract("main.go", src)
    caller_id = next(s.id for s in u.symbols if s.name == "caller")
    assert (caller_id, "helper", 3) in u.calls


def test_method_call_via_selector_uses_the_field_name() -> None:
    src = b"""
package main
type Server struct{}
func (s *Server) Handle() { s.process() }
func (s *Server) process() {}
"""
    u = extract("main.go", src)
    caller_id = next(s.id for s in u.symbols if s.qualified_name == "Server.Handle")
    assert (caller_id, "process", 4) in u.calls


def test_http_handlefunc_is_an_entrypoint_with_a_call_to_the_handler() -> None:
    src = b"""
package main
import "net/http"
func handler(w http.ResponseWriter, r *http.Request) {}
func main() {
	http.HandleFunc("/users", handler)
}
"""
    u = extract("main.go", src)
    assert len(u.entrypoints) == 1
    ep = u.entrypoints[0]
    assert ep.framework == "net/http" and ep.path == "/users"
    assert (ep.symbol_id, "handler", 6) in u.calls


def test_mux_handle_on_any_receiver_name_is_also_matched() -> None:
    """Resolving whether `mux` is really a `*http.ServeMux` needs real type inference this pass
    doesn't do -- matched by method-name shape instead, same as the other languages' route
    detection; documented, not hidden."""
    src = b"""
package main
func main() {
	mux.HandleFunc("/api", apiHandler)
}
func apiHandler() {}
"""
    u = extract("main.go", src)
    assert len(u.entrypoints) == 1
    assert u.entrypoints[0].path == "/api"


def test_a_plain_function_call_is_not_an_entrypoint() -> None:
    src = b"""
package main
func main() { doWork() }
func doWork() {}
"""
    u = extract("main.go", src)
    assert u.entrypoints == []


def test_syntax_error_is_reported_as_unparsed_not_raised() -> None:
    u = extract("broken.go", b"func f( {")
    assert u.parsed is False
