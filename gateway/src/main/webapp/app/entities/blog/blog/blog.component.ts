import { Component, OnInit, OnDestroy } from '@angular/core';
import { HttpErrorResponse, HttpResponse } from '@angular/common/http';
import { ActivatedRoute } from '@angular/router';
import { Subscription } from 'rxjs';
import { filter, map } from 'rxjs/operators';
import { JhiEventManager, JhiAlertService } from 'ng-jhipster';

import { IBlog } from 'app/shared/model/blog/blog.model';
import { AccountService } from 'app/core';
import { BlogService } from './blog.service';

@Component({
  selector: 'jhi-blog',
  templateUrl: './blog.component.html'
})
export class BlogComponent implements OnInit, OnDestroy {
  blogs: IBlog[];
  currentAccount: any;
  eventSubscriber: Subscription;
  currentSearch: string;

  constructor(
    protected blogService: BlogService,
    protected jhiAlertService: JhiAlertService,
    protected eventManager: JhiEventManager,
    protected activatedRoute: ActivatedRoute,
    protected accountService: AccountService
  ) {
    this.currentSearch =
      this.activatedRoute.snapshot && this.activatedRoute.snapshot.params['search'] ? this.activatedRoute.snapshot.params['search'] : '';
  }

  loadAll() {
    if (this.currentSearch) {
      this.blogService
        .search({
          query: this.currentSearch
        })
        .pipe(
          filter((res: HttpResponse<IBlog[]>) => res.ok),
          map((res: HttpResponse<IBlog[]>) => res.body)
        )
        .subscribe((res: IBlog[]) => (this.blogs = res), (res: HttpErrorResponse) => this.onError(res.message));
      return;
    }
    this.blogService
      .query()
      .pipe(
        filter((res: HttpResponse<IBlog[]>) => res.ok),
        map((res: HttpResponse<IBlog[]>) => res.body)
      )
      .subscribe(
        (res: IBlog[]) => {
          this.blogs = res;
          this.currentSearch = '';
        },
        (res: HttpErrorResponse) => this.onError(res.message)
      );
  }

  search(query) {
    if (!query) {
      return this.clear();
    }
    this.currentSearch = query;
    this.loadAll();
  }

  clear() {
    this.currentSearch = '';
    this.loadAll();
  }

  ngOnInit() {
    this.loadAll();
    this.accountService.identity().then(account => {
      this.currentAccount = account;
    });
    this.registerChangeInBlogs();
  }

  ngOnDestroy() {
    this.eventManager.destroy(this.eventSubscriber);
  }

  trackId(index: number, item: IBlog) {
    return item.id;
  }

  registerChangeInBlogs() {
    this.eventSubscriber = this.eventManager.subscribe('blogListModification', response => this.loadAll());
  }

  protected onError(errorMessage: string) {
    this.jhiAlertService.error(errorMessage, null, null);
  }
}
