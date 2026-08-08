"""Minimal LangGraph demo using runtime identity binding and engine RPC."""

from __future__ import annotations

from typing import TypedDict

from langgraph.graph import END, StateGraph

from hyperbus_runtime.worker import bind_from_env, checkpointer, inject_langgraph_config


class DemoState(TypedDict):
    messages: list[str]


def echo_node(state: DemoState) -> DemoState:
    last = state["messages"][-1] if state["messages"] else ""
    return {"messages": state["messages"] + [f"echo:{last}"]}


def build_graph():
    bind_from_env()
    graph = StateGraph(DemoState)
    graph.add_node("echo", echo_node)
    graph.set_entry_point("echo")
    graph.add_edge("echo", END)
    return graph.compile(checkpointer=checkpointer())


if __name__ == "__main__":
    app = build_graph()
    config = inject_langgraph_config(
        {"configurable": {"thread_id": "demo-thread-1"}}
    )
    result = app.invoke({"messages": ["hello-hyperbus"]}, config)
    print(result)
