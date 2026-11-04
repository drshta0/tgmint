from __future__ import annotations
import inspect
import typing


class OpenTeleException(Exception):  # nocov
    """
    Base exception of the library.

    fork note: upstream inherited from BaseException, which meant these
    errors escaped every `except Exception:` handler (asyncio, loggers,
    generic cleanup). Now a normal Exception.
    """

    def __init__(self, message: str = None, stack_index: int = 1) -> None:

        super().__init__(message if (message != None) else "")

        self.message = message
        self.desc = self.__class__.__name__

        # fork note: upstream stored `self.frame = inspect.currentframe()`
        # (and walked it lazily in __str__), which pinned every caller
        # local — passwords, keys, sessions — in memory for as long as the
        # exception object lived. We derive the caller info eagerly, keep
        # only plain strings, and let go of the frame before returning.
        frame = inspect.currentframe()
        try:
            for _ in range(stack_index):
                if frame.f_back is None:
                    break
                frame = frame.f_back

            self._caller_class_name = (
                frame.f_locals["self"].__class__.__name__
                if "self" in frame.f_locals
                else None
            )
            self._caller_method = frame.f_code.co_name

            if self._caller_method != "<module>":
                args, _, _, locals = inspect.getargvalues(frame)
                parameters = {arg: locals[arg] for arg in args}
                self._caller_method_params = "".join(
                    f"{i}={parameters[i]}, " for i in parameters
                )[:-2]
            else:
                self._caller_method = "__main__"
                self._caller_method_params = ""
        finally:
            # drop the last reference to the caller's frame
            frame = None

        if self.desc == "OpenTeleException":
            self.desc = "Unexpected Exception"

    def __str__(self):
        reason = self.desc.__str__()

        if self.message != None:
            reason += f": {self.message}"

        reason += " [ Called by "
        if self._caller_class_name != None:
            reason += f"{self._caller_class_name}.{self._caller_method}() ]"
            # reason += f"\n>\t{self._caller_method}({self._caller_method_params})"
        else:
            reason += f"{self._caller_method}() ]"
            # reason += f"{self._caller_method}({self._caller_method_params}) ]"
        return reason


class TFileNotFound(OpenTeleException):
    """
    Could not find or open the file
    """


class TDataInvalidMagic(OpenTeleException):
    """
    TData file has an invalid magic data, which is the first 4 bytes of the file\n
    This usually mean that the file is corrupted or not in the supported formats
    """


class TDataInvalidCheckSum(OpenTeleException):
    """
    TData file has an invalid checksum\n
    This usually mean that the file is corrupted or not in the supported formats
    """


class TDataBadDecryptKey(OpenTeleException):
    """
    Could not decrypt the data with this key\n
    This usually mean that the file is password-encrypted
    """


class TDataWrongPasscode(OpenTeleException):
    """
    Wrong passcode to decrypt tdata folder\n
    """


class TDataBadEncryptedDataSize(OpenTeleException):
    """
    The encrypted data size part of the file is corrupted
    """


class TDataBadDecryptedDataSize(OpenTeleException):
    """
    The decrypted data size part of the file is corrupted
    """


class TDataBadConfigData(OpenTeleException):
    """
    TData contains bad config data that couldn't be parsed
    """


class QDataStreamFailed(OpenTeleException):
    """
    Could not stream data from QDataStream\n
    Please check the QDataStream.status() for more information
    """


class AccountAuthKeyNotFound(OpenTeleException):
    """
    Account.authKey is missing, something went wrong
    """


class TDataReadMapDataFailed(OpenTeleException):
    """
    Could not read map data
    """


class TDataReadMapDataIncorrectPasscode(OpenTeleException):
    """
    Could not read map data because of incorrect passcode
    """


class TDataAuthKeyNotFound(OpenTeleException):
    """
    Could not find authKey in TData
    """


class MaxAccountLimit(OpenTeleException):
    """
    Maxed out limit for accounts per tdesktop client
    """


class TDesktopUnauthorized(OpenTeleException):
    """
    TDesktop client is unauthorized
    """


class TelethonUnauthorized(OpenTeleException):
    """
    Telethon client is unauthorized
    """


class TDataSaveFailed(OpenTeleException):
    """
    Could not save TDesktop to tdata folder
    """


class TDesktopNotLoaded(OpenTeleException):
    """
    TDesktop instance has no account
    """


class TDesktopHasNoAccount(OpenTeleException):
    """
    TDesktop instance has no account
    """


class TDAccountNotLoaded(OpenTeleException):
    """
    TDesktop account hasn't been loaded yet
    """


class NoPasswordProvided(OpenTeleException):
    """
    You can't live without a password bro
    """


class PasswordIncorrect(OpenTeleException):
    """
    incorrect passwrd
    """


class LoginFlagInvalid(OpenTeleException):
    """
    Invalid login flag
    """


class NoInstanceMatched(OpenTeleException):
    """
    Invalid login flag
    """


@typing.overload
def Expects(
    condition: bool,
    message: str = None,
    done: typing.Callable[[], None] = None,
    fail: typing.Callable[[OpenTeleException], None] = None,
    silent: bool = False,
    stack_index: int = 1,
) -> bool:
    """Expect a condition to be `True`, raise an `OpenTeleException` if it's not.

    ### Arguments:
        condition (bool):
            Condition that you're expecting.

        message (str, default=None):
            Custom exception message

        done (`lambda`, default=None):
            lambda to execute when done without error

        fail (`lambda`, default=None):
            lambda to execute when the condition is False, the lambda will be execute before raising the exception.

        silent (`bool`, default=False):
            if True then it won't raise the exception, only execute fail lambda.

        stack_index (`int`, default=1):
            stack index to raise the exception with trace back to where it happens, intended for internal usage.

    ### Raises:
        `OpenTeleException`: exception
    """


@typing.overload
def Expects(
    condition: bool,
    exception: OpenTeleException = None,
    done: typing.Callable[[], None] = None,
    fail: typing.Callable[[OpenTeleException], None] = None,
    silent: bool = False,
    stack_index: int = 1,
) -> bool:

    """Expect a condition to be `True`, raise an `OpenTeleException` if it's not.

    ### Arguments:
        condition (bool):
            Condition that you're expecting.

        message (OpenTeleException, default=None):
            Custom exception.

        done (`lambda`, default=None):
            lambda to execute when done without error.

        fail (`lambda`, default=None):
            lambda to execute when the condition is False, the lambda will be execute before raising the exception.

        silent (`bool`, default=False):
            if True then it won't raise the exception, only execute fail lambda.

        stack_index (`int`, default=1):
            stack index to raise the exception with trace back to where it happens, intended for internal usage.

    ### Raises:
        `OpenTeleException`: exception
    """


def Expects(
    condition: bool,
    exception: typing.Union[OpenTeleException, str] = None,
    done: typing.Callable[[], None] = None,
    fail: typing.Callable[[OpenTeleException], None] = None,
    silent: bool = False,
    stack_index: int = 1,
) -> bool:  # nocov

    if condition:
        if done != None:
            done()
        return condition

    if isinstance(exception, str):
        exception = OpenTeleException(exception, 2)

    elif exception != None and not isinstance(exception, OpenTeleException):
        raise OpenTeleException("No instance of Expects() match the arguments given", 2)

    if exception == None:
        exception = OpenTeleException("Unexpected error", 2)

    # no raise exception
    if silent:
        if fail != None:
            fail(exception)
        return condition

    else:
        # fork note: upstream built a synthetic traceback here from
        # inspect.stack() — slow, and it pinned every frame up the call
        # chain on the exception object. The exception is now raised
        # normally; the real traceback already leads back to the caller,
        # so `stack_index` is no longer needed to fabricate one (it stays
        # in the signature for API compatibility).
        if fail != None:
            fail(exception)

        raise exception


def ExpectStreamStatus(stream: QDataStream, message: str = "Could not stream data"):
    # fork note: lazy import — this helper is only reached during tdata
    # streaming; the rest of the library must import without Qt installed
    from PyQt5.QtCore import QDataStream

    Expects(
        stream.status() == QDataStream.Status.Ok,
        stack_index=2,
        exception=QDataStreamFailed(
            "Could not read keys count from mtp authorization.", stack_index=2
        ),
    )
