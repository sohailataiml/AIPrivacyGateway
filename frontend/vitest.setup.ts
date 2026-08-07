import { cleanup } from "@testing-library/react";
import { afterEach, beforeEach } from "vitest";

/**
 * No `@testing-library/jest-dom`. The matchers it adds are convenience over
 * assertions that plain `expect` can already make against `textContent`,
 * attributes, and `document.querySelector`, and adding a dependency that the
 * Render build would also have to install is not worth the sugar.
 */

/**
 * jsdom does not implement `HTMLDialogElement.showModal`, so a `<dialog>`
 * rendered in a test never opens and every assertion about its contents fails
 * for a reason that has nothing to do with the component. These shims give it
 * the one behaviour the tests depend on: `open` reflects whether it is showing.
 */
beforeEach(() => {
  if (!HTMLDialogElement.prototype.showModal) {
    HTMLDialogElement.prototype.showModal = function showModal(this: HTMLDialogElement) {
      this.open = true;
    };
  }
  if (!HTMLDialogElement.prototype.close) {
    HTMLDialogElement.prototype.close = function close(this: HTMLDialogElement) {
      this.open = false;
      this.dispatchEvent(new Event("close"));
    };
  }
});

afterEach(() => {
  cleanup();
});
