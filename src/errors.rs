/*
 * Copyright (C) 2021  Aravinth Manivannan <realaravinth@batsense.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

use std::convert::From;

use derive_more::{Display, Error};
use base64::DecodeError as Base64Error;
use multihash::Error as MultihashError;

#[derive(Debug, Display, Error)]
#[cfg(not(tarpaulin_include))]
pub enum ServiceError {
    #[display(fmt = "{}", _0)]
    Base64Error(Base64Error),

    #[display(fmt = "{}", _0)]
    MultihashError(MultihashError),

}

impl From<Base64Error> for ServiceError {
    #[cfg(not(tarpaulin_include))]
    fn from(e: Base64Error) -> ServiceError {
        ServiceError::Base64Error(e)
    }
}

impl From<MultihashError> for ServiceError {
    #[cfg(not(tarpaulin_include))]
    fn from(e: MultihashError) -> ServiceError {
        ServiceError::MultihashError(e)
    }
}

#[cfg(not(tarpaulin_include))]
pub type ServiceResult<V> = std::result::Result<V, ServiceError>;
