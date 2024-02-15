// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Contains an implementation of a tracing subscriber specialized for collecting data about
//! tokio-based async unit tests.

use std::{
    cell::RefCell,
    collections::HashMap,
    sync::{Arc, Mutex},
};

use tokio::time::Instant;
use tracing_core::span::Current;

// Key-value pairs that can be extracted from tracing events. All value types are converted to
// string form.
struct Labels(Vec<(&'static str, String)>);

impl Labels {
    fn new() -> Self {
        Labels(Vec::new())
    }
}

impl tracing::field::Visit for Labels {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.push((field.name(), format!("{value:?}")))
    }
}

impl std::ops::Deref for Labels {
    type Target = Vec<(&'static str, String)>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

enum Item {
    Event(Event),
    Span(u64),
}

// Represents a tracing event (eg. tracing::info!).
struct Event {
    timestamp: Instant,
    labels: Labels,
}

impl Event {
    fn new(event: &tracing::Event<'_>) -> Self {
        let mut labels = Labels::new();
        event.record(&mut labels);
        Event {
            labels,
            timestamp: Instant::now(),
        }
    }
}

struct Span {
    labels: Labels,
    meta: &'static tracing::Metadata<'static>,
    items: Vec<Item>,
    // The first time the span was entered.
    enter: Option<Instant>,
    // The last time the span was exited.
    last_exit: Option<Instant>,
    // Whether the span has been closed.
    closed: bool,
}

impl Span {
    fn new(attrs: &tracing::span::Attributes<'_>) -> Self {
        let mut labels = Labels::new();
        attrs.values().record(&mut labels);
        Span {
            labels,
            enter: None,
            last_exit: None,
            closed: false,
            meta: attrs.metadata(),
            items: Vec::new(),
        }
    }

    // Returns the time the Span was last exited, if it is closed. In particular it means this will
    // return None for instrumented async functions that have made some (but not all) progress in
    // their execution.
    fn exit(&self) -> Option<Instant> {
        if self.closed {
            self.last_exit
        } else {
            None
        }
    }
}

// A collection of Spans that automatically assigns them unique IDs.
#[derive(Default)]
struct State {
    spans: HashMap<u64, Span>,
    root: Vec<Item>,
    last_span_id: u64,
}

impl State {
    fn add_span(&mut self, span: Span) -> u64 {
        self.last_span_id += 1;
        self.spans.insert(self.last_span_id, span);
        self.last_span_id
    }

    fn get_span(&self, id: u64) -> &Span {
        self.spans.get(&id).unwrap()
    }

    fn get_span_mut(&mut self, id: u64) -> &mut Span {
        self.spans.get_mut(&id).unwrap()
    }
}

/// A tracing subscriber that collects all data for later structured formatting. The collected data
/// can be retrieved using an associated Formatter (also returned by new_subscribed).
pub struct Subscriber {
    state: Arc<Mutex<State>>,
}

impl Subscriber {
    thread_local! {
        static SPAN_STACK: RefCell<Vec<u64>>  = Default::default()
    }

    fn with_span(&self, id: &tracing::Id, f: impl FnOnce(&mut Span)) {
        let mut state = self.state.lock().unwrap();
        f(state.get_span_mut(id.into_u64()));
    }

    fn with_current_span<R>(&self, f: impl FnOnce(Option<(u64, &mut Span)>) -> R) -> R {
        let mut state = self.state.lock().unwrap();
        Self::SPAN_STACK.with(|stack| {
            f(stack
                .borrow()
                .last()
                .map(|id| (*id, state.get_span_mut(*id))))
        })
    }

    fn current_span_items<'a>(&self, state: &'a mut State) -> &'a mut Vec<Item> {
        match Self::SPAN_STACK.with(|stack| stack.borrow().last().copied()) {
            None => &mut state.root,
            Some(id) => &mut state.get_span_mut(id).items,
        }
    }

    // If id is None then the current span is returned.
    fn parent_span_items<'a>(
        &self,
        id: Option<&tracing::Id>,
        state: &'a mut State,
    ) -> &'a mut Vec<Item> {
        match id {
            Some(id) => &mut state.get_span_mut(id.into_u64()).items,
            None => self.current_span_items(state),
        }
    }
}

impl tracing::Subscriber for Subscriber {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, attrs: &tracing::span::Attributes<'_>) -> tracing::Id {
        let mut state = self.state.lock().unwrap();
        let id = state.add_span(Span::new(attrs));
        self.parent_span_items(attrs.parent(), &mut state)
            .push(Item::Span(id));
        tracing::Id::from_u64(id)
    }

    fn record(&self, span_id: &tracing::Id, values: &tracing::span::Record<'_>) {
        let mut state = self.state.lock().unwrap();
        let labels = &mut state.get_span_mut(span_id.into_u64()).labels;
        values.record(labels);
    }

    fn record_follows_from(&self, _span: &tracing::Id, _follows: &tracing::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut state = self.state.lock().unwrap();
        self.parent_span_items(event.parent(), &mut state)
            .push(Item::Event(Event::new(event)));
    }

    fn enter(&self, span_id: &tracing::Id) {
        self.with_span(span_id, |span| {
            Self::SPAN_STACK.with(|stack| {
                stack.borrow_mut().push(span_id.into_u64());
            });
            if span.enter.is_none() {
                span.enter = Some(Instant::now());
            }
        });
    }

    fn exit(&self, span_id: &tracing::Id) {
        self.with_span(span_id, |span| {
            span.last_exit = Some(Instant::now());
            Self::SPAN_STACK.with(|stack| {
                stack.borrow_mut().pop().unwrap();
            });
        });
    }

    fn try_close(&self, span_id: tracing_core::span::Id) -> bool {
        self.with_span(&span_id, |span| {
            span.closed = true;
        });
        true
    }

    fn current_span(&self) -> Current {
        self.with_current_span(|span| match span {
            Some((id, span)) => Current::new(tracing::Id::from_u64(id), span.meta),
            None => Current::none(),
        })
    }
}

/// Provides ways to pretty-print information gathered by the associated Subscriber. It prints
/// timestamps (as defined by tokio::time::Instant::now() relative to the time the
/// Formatter/Subscriber pair was created. This provides for small, readable timestamps in tests
/// with paused time.
pub struct Formatter {
    spans: Arc<Mutex<State>>,
    root: String,
    epoch: tokio::time::Instant,
}

impl Formatter {
    fn new(spans: Arc<Mutex<State>>, root: String) -> Self {
        Formatter {
            spans,
            root,
            epoch: tokio::time::Instant::now(),
        }
    }

    /// Pretty-prints information gathered by the associated Subscriber to the specified writer.
    pub fn write<W: std::fmt::Write>(&self, w: &mut W) -> std::fmt::Result {
        let spans = self.spans.lock().unwrap();

        struct Env<'a, W> {
            w: &'a mut W,
            indent: u32,
            spans: &'a State,
            epoch: tokio::time::Instant,
        }

        impl<'a, W: std::fmt::Write> Env<'a, W> {
            // Formats the Instant as the (possibly fractional) number of milliseconds since the
            // configured epoch. We use milliseconds because that's tokio's time granularity.
            fn fmttime(&self, ts: Instant) -> String {
                const NS_IN_MS: u128 = 1_000_000;
                let ns = ts.duration_since(self.epoch).as_nanos();
                let ms = ns / NS_IN_MS;
                let subms_ns = (ns % NS_IN_MS) as u32;
                if subms_ns != 0 {
                    // Compute fractional part of the millisecond value, but be exact (so we don't
                    // use floats). Not sure this can happen in practice, perhaps only if we call
                    // advance with a very granular value?
                    let mut fraction = subms_ns;
                    while fraction % 10 == 0 {
                        fraction /= 10;
                    }
                    format!("{ms}ms.{fraction}")
                } else {
                    ms.to_string()
                }
            }

            fn write_indent(&mut self) -> std::fmt::Result {
                for _ in 0..self.indent {
                    self.w.write_char(' ')?;
                }
                Ok(())
            }
        }

        // Returns the time the last item finished.
        fn write<W: std::fmt::Write>(
            env: &mut Env<W>,
            items: &Vec<Item>,
        ) -> Result<Option<Instant>, std::fmt::Error> {
            let mut exit = None;
            for item in items {
                match item {
                    Item::Span(id) => {
                        let span = env.spans.get_span(*id);
                        write_span(env, span)?;
                        exit = span.exit();
                    }
                    Item::Event(event) => {
                        write_event(env, event)?;
                        exit = Some(event.timestamp);
                    }
                }
            }
            Ok(exit)
        }

        fn write_event<W: std::fmt::Write>(env: &mut Env<W>, event: &Event) -> std::fmt::Result {
            env.write_indent()?;
            write!(env.w, "@{}", env.fmttime(event.timestamp))?;
            for (k, v) in event.labels.iter() {
                if k == &"message" {
                    write!(env.w, " {v}")?
                } else {
                    write!(env.w, " {k}={v}")?
                }
            }
            env.w.write_char('\n')?;
            Ok(())
        }

        fn write_span<W: std::fmt::Write>(env: &mut Env<W>, span: &Span) -> std::fmt::Result {
            // Span header.
            env.write_indent()?;
            if span.items.is_empty() {
                match (span.enter, span.exit()) {
                    (Some(enter), Some(exit)) => {
                        if enter == exit {
                            write!(env.w, "@{} ", env.fmttime(enter))?;
                        } else {
                            write!(env.w, "@{}-{} ", env.fmttime(enter), env.fmttime(exit))?;
                        }
                    }
                    (Some(enter), None) => write!(env.w, "@{}-? ", env.fmttime(enter))?,
                    (None, Some(exit)) => write!(env.w, "@?-{} ", env.fmttime(exit))?,
                    (None, None) => (),
                }
            } else if let Some(ts) = span.enter {
                write!(env.w, "@{} ", env.fmttime(ts))?;
            }
            env.w.write_str(span.meta.name())?;
            for (k, v) in span.labels.iter() {
                write!(env.w, " {k}={v}")?
            }
            env.w.write_char('\n')?;

            // Children.
            env.indent += 2;
            if let Some(items_exit) = write(env, &span.items)? {
                if let Some(exit) = span.exit() {
                    if items_exit < exit {
                        env.write_indent()?;
                        writeln!(env.w, "@{} (done)", env.fmttime(exit))?;
                    }
                } else {
                    env.w.write_str("(still running)")?;
                }
            }
            env.indent -= 2;

            Ok(())
        }

        w.write_str(self.root.as_str())?;
        w.write_char('\n')?;
        let mut env = Env {
            w,
            indent: 2,
            spans: &spans,
            epoch: self.epoch,
        };
        write(&mut env, &spans.root)?;
        Ok(())
    }
}

/// Creates a new Subscriber with an associated Formatter.
pub fn new_subscriber(root: String) -> (Subscriber, Formatter) {
    let spans: Arc<Mutex<State>> = Default::default();
    let sub = Subscriber {
        state: spans.clone(),
    };
    let fmt = Formatter::new(spans, root);
    (sub, fmt)
}

/// On drop uninstalls the associated Subscriber and prints collected data.
pub struct PrintGuard {
    fmt: Formatter,
    _default: tracing::subscriber::DefaultGuard,
}

impl Drop for PrintGuard {
    fn drop(&mut self) {
        let mut s = String::new();
        self.fmt.write(&mut s).unwrap();
        print!("{s}");
    }
}

/// Sets a new Subscriber as the default tracing subscriber for the calling thread (unit test) and
/// returns a guard that will print gathered data on drop (likely at the end of the test).
pub fn print_on_exit() -> PrintGuard {
    let root = std::thread::current()
        .name()
        .unwrap_or("<unknown>")
        .to_string();
    let (sub, fmt) = new_subscriber(root);
    let default = tracing::subscriber::set_default(sub);
    PrintGuard {
        fmt,
        _default: default,
    }
}
