//! Command-line arguments of the `kanbot-backend` binary.

/// What the binary was asked to do.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    /// No arguments: serve the HTTP API.
    Serve,
    /// `migrate`: apply pending database migrations, then exit.
    Migrate,
}

#[derive(Debug, thiserror::Error)]
#[error("usage: kanbot-backend [migrate]")]
pub struct UsageError;

impl Command {
    /// Parses the arguments after the program name.
    ///
    /// # Errors
    ///
    /// Returns [`UsageError`] for anything but no arguments or `migrate`.
    pub fn parse<I, S>(args: I) -> Result<Self, UsageError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut args = args.into_iter();
        let command = match args.next() {
            None => Self::Serve,
            Some(arg) if arg.as_ref() == "migrate" => Self::Migrate,
            Some(_) => return Err(UsageError),
        };
        match args.next() {
            None => Ok(command),
            Some(_) => Err(UsageError),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_arguments_serve() {
        assert_eq!(Command::parse::<_, &str>([]).unwrap(), Command::Serve);
    }

    #[test]
    fn migrate_migrates() {
        assert_eq!(Command::parse(["migrate"]).unwrap(), Command::Migrate);
    }

    #[test]
    fn rejects_anything_else() {
        for args in [&["serve"][..], &["MIGRATE"], &["migrate", "now"], &[""]] {
            assert!(Command::parse(args).is_err(), "{args:?}");
        }
    }
}
