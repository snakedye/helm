use crate::vm::{op::Op, scanner::Scanner};

/// Trait implemented by all macro iterators that yield `Op` items.
///
/// It is a supertrait of `Iterator<Item = Op<'a>>`, allowing macro iterators
/// to be used uniformly through a `Box<dyn OpMacro<'a> + 'a>`.
pub trait OpMacro<'a>: Iterator<Item = Op<'a>> {}

// Blanket impl: every iterator that yields `Op<'a>` is automatically an `OpMacro<'a>`.
impl<'a, T: Iterator<Item = Op<'a>>> OpMacro<'a> for T {}

#[derive(Debug, Clone, PartialEq)]
/// A decoded expression produced by the [`Scanner`].
pub enum Expr<'a> {
    /// A single, immediately-available opcode.
    Op(Op<'a>),
    /// A clone-macro expansion that repeats one opcode N times.
    Clone { scanner: Scanner<'a>, count: u8 },
    /// A static-macro expansion that re-scans a pre-encoded byte slice.
    Sequence(Scanner<'a>),
}

impl<'a> Expr<'a> {
    pub fn seq(bytes: &'a [u8]) -> Self {
        Expr::Sequence(Scanner::new(bytes))
    }
    pub fn clone(scanner: Scanner<'a>, count: u8) -> Self {
        Expr::Clone { scanner, count }
    }
}

impl<'a> From<Op<'a>> for Expr<'a> {
    fn from(op: Op<'a>) -> Self {
        Expr::Op(op)
    }
}

impl<'a> TryInto<Op<'a>> for Expr<'a> {
    type Error = ();

    fn try_into(self) -> Result<Op<'a>, Self::Error> {
        match self {
            Expr::Op(op) => Ok(op),
            _ => Err(()),
        }
    }
}

impl<'a> IntoIterator for Expr<'a> {
    type Item = Op<'a>;
    type IntoIter = Box<dyn OpMacro<'a> + 'a>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            Expr::Op(op) => Box::new(std::iter::once(op)),
            Expr::Clone { mut scanner, count } => Box::new(
                std::iter::repeat_n(scanner.next(), count as usize)
                    .flatten()
                    .flatten(),
            ),
            Expr::Sequence(m) => Box::new(m.flatten()),
        }
    }
}
